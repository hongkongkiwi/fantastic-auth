//! Common migration models and types

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Migration source types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "migration_source", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum MigrationSource {
    Auth0,
    Firebase,
    Cognito,
    Csv,
    Ldap,
    Okta,
    OneLogin,
}

impl MigrationSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            MigrationSource::Auth0 => "auth0",
            MigrationSource::Firebase => "firebase",
            MigrationSource::Cognito => "cognito",
            MigrationSource::Csv => "csv",
            MigrationSource::Ldap => "ldap",
            MigrationSource::Okta => "okta",
            MigrationSource::OneLogin => "onelogin",
        }
    }
}

impl std::str::FromStr for MigrationSource {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "auth0" => Ok(MigrationSource::Auth0),
            "firebase" => Ok(MigrationSource::Firebase),
            "cognito" => Ok(MigrationSource::Cognito),
            "csv" => Ok(MigrationSource::Csv),
            "ldap" => Ok(MigrationSource::Ldap),
            "okta" => Ok(MigrationSource::Okta),
            "onelogin" => Ok(MigrationSource::OneLogin),
            _ => Err(format!("Unknown migration source: {}", s)),
        }
    }
}

/// Migration job status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "migration_status", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum MigrationStatus {
    Pending,
    Running,
    Paused,
    Completed,
    Failed,
    Cancelled,
}

impl MigrationStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            MigrationStatus::Pending => "pending",
            MigrationStatus::Running => "running",
            MigrationStatus::Paused => "paused",
            MigrationStatus::Completed => "completed",
            MigrationStatus::Failed => "failed",
            MigrationStatus::Cancelled => "cancelled",
        }
    }

    pub fn is_active(&self) -> bool {
        matches!(self, MigrationStatus::Pending | MigrationStatus::Running)
    }

    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            MigrationStatus::Completed | MigrationStatus::Failed | MigrationStatus::Cancelled
        )
    }
}

/// Migration job record
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct MigrationJob {
    pub id: String,
    pub tenant_id: String,
    pub source: MigrationSource,
    pub status: MigrationStatus,
    pub total_users: i32,
    pub processed: i32,
    pub succeeded: i32,
    pub failed: i32,
    pub config: serde_json::Value,
    pub dry_run: bool,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub created_by: Option<String>,
    pub resumed_from: Option<String>,
    pub last_processed_id: Option<String>,
}

/// Migration error record
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct MigrationErrorRecord {
    pub id: String,
    pub migration_id: String,
    pub external_id: Option<String>,
    pub email: Option<String>,
    pub error_message: String,
    pub error_details: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
}

/// Migration error (in-memory representation)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationError {
    pub user_id: String,
    pub email: Option<String>,
    pub error: String,
    pub details: Option<serde_json::Value>,
}

/// Migration result summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationResult {
    pub job_id: String,
    pub total: usize,
    pub migrated: usize,
    pub failed: usize,
    pub skipped: usize,
    pub errors: Vec<MigrationError>,
    pub duration_secs: u64,
    pub dry_run: bool,
}

impl MigrationResult {
    pub fn new(job_id: String, dry_run: bool) -> Self {
        Self {
            job_id,
            total: 0,
            migrated: 0,
            failed: 0,
            skipped: 0,
            errors: Vec::new(),
            duration_secs: 0,
            dry_run,
        }
    }

    pub fn add_success(&mut self) {
        self.migrated += 1;
    }

    pub fn add_failure(&mut self, error: MigrationError) {
        self.failed += 1;
        self.errors.push(error);
    }

    pub fn add_skipped(&mut self) {
        self.skipped += 1;
    }

    pub fn success_rate(&self) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        (self.migrated as f64 / self.total as f64) * 100.0
    }
}

/// Migration progress for real-time updates
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationProgress {
    pub id: String,
    pub source: String,
    pub status: MigrationStatus,
    pub total_users: usize,
    pub processed: usize,
    pub succeeded: usize,
    pub failed: usize,
    pub percent_complete: f64,
    pub estimated_remaining_secs: Option<u64>,
    pub current_operation: Option<String>,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub errors_count: usize,
}

impl MigrationProgress {
    pub fn percent_complete(&self) -> f64 {
        if self.total_users == 0 {
            return 0.0;
        }
        (self.processed as f64 / self.total_users as f64) * 100.0
    }

    pub fn estimated_remaining_secs(&self) -> Option<u64> {
        if self.processed == 0 || self.status != MigrationStatus::Running {
            return None;
        }

        let elapsed = Utc::now().signed_duration_since(self.started_at);
        let elapsed_secs = elapsed.num_seconds().max(1) as u64;
        let rate = self.processed as f64 / elapsed_secs as f64;
        let remaining = self.total_users.saturating_sub(self.processed) as f64 / rate;

        Some(remaining as u64)
    }
}

/// Common migration options
#[derive(Debug, Clone, Deserialize)]
pub struct MigrationOptions {
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,
    #[serde(default)]
    pub skip_existing: bool,
    #[serde(default)]
    pub update_existing: bool,
    #[serde(default)]
    pub import_passwords: bool,
    #[serde(default)]
    pub import_mfa: bool,
    #[serde(default)]
    pub generate_passwords: bool,
    #[serde(default)]
    pub send_welcome_email: bool,
    #[serde(default)]
    pub custom_mappings: HashMap<String, String>,
}

impl Default for MigrationOptions {
    fn default() -> Self {
        Self {
            dry_run: false,
            batch_size: default_batch_size(),
            skip_existing: true,
            update_existing: false,
            import_passwords: false,
            import_mfa: false,
            generate_passwords: false,
            send_welcome_email: false,
            custom_mappings: HashMap::new(),
        }
    }
}

fn default_batch_size() -> usize {
    100
}

/// OAuth connection from external provider
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalOAuthConnection {
    pub provider: String,
    pub provider_user_id: String,
    pub provider_username: Option<String>,
    pub email: Option<String>,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub token_expires_at: Option<DateTime<Utc>>,
    pub raw_data: Option<serde_json::Value>,
}

/// MFA method from external provider
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalMfaMethod {
    pub method_type: String,
    pub enabled: bool,
    pub data: serde_json::Value,
}

/// Common user data extracted from any source
#[derive(Debug, Clone, Default)]
pub struct ExternalUser {
    pub external_id: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub username: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub display_name: Option<String>,
    pub phone_number: Option<String>,
    pub phone_verified: bool,
    pub picture: Option<String>,
    pub password_hash: Option<String>,
    pub password_salt: Option<String>,
    pub status: Option<String>,
    pub created_at: Option<DateTime<Utc>>,
    pub last_login_at: Option<DateTime<Utc>>,
    pub last_ip: Option<String>,
    pub logins_count: Option<i32>,
    pub metadata: HashMap<String, serde_json::Value>,
    pub oauth_connections: Vec<ExternalOAuthConnection>,
    pub mfa_methods: Vec<ExternalMfaMethod>,
    pub enabled: bool,
    pub locked: bool,
}

impl ExternalUser {
    /// Get the primary identifier for this user
    pub fn primary_identifier(&self) -> String {
        self.email
            .clone()
            .or_else(|| self.username.clone())
            .unwrap_or_else(|| self.external_id.clone())
    }

    /// Check if this user has valid data for migration
    pub fn is_valid(&self) -> bool {
        // Must have at least an email or username
        self.email.is_some() || self.username.is_some()
    }

    /// Convert metadata to JSON value
    pub fn metadata_json(&self) -> serde_json::Value {
        serde_json::to_value(&self.metadata).unwrap_or_else(|_| serde_json::json!({}))
    }
}

/// Request to create a user from migration
#[derive(Debug, Clone)]
pub struct CreateUserFromMigration {
    pub tenant_id: String,
    pub email: String,
    pub email_verified: bool,
    pub password_hash: Option<String>,
    pub profile: Option<serde_json::Value>,
    pub metadata: Option<serde_json::Value>,
    pub external_id: Option<String>,
    pub source: String,
    pub status: Option<String>,
    pub created_at: Option<DateTime<Utc>>,
    pub oauth_connections: Vec<ExternalOAuthConnection>,
    pub mfa_methods: Vec<ExternalMfaMethod>,
}

/// Validation result for external user
#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

impl ValidationResult {
    pub fn valid() -> Self {
        Self {
            valid: true,
            errors: Vec::new(),
            warnings: Vec::new(),
        }
    }

    pub fn with_error(mut self, error: impl Into<String>) -> Self {
        self.valid = false;
        self.errors.push(error.into());
        self
    }

    pub fn with_warning(mut self, warning: impl Into<String>) -> Self {
        self.warnings.push(warning.into());
        self
    }
}

/// Rate limiting configuration for migrations
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    pub requests_per_second: f64,
    pub burst_size: usize,
    pub delay_between_batches_ms: u64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_second: 10.0,
            burst_size: 100,
            delay_between_batches_ms: 100,
        }
    }
}

/// Token bucket rate limiter
pub struct TokenBucket {
    tokens: f64,
    last_update: std::time::Instant,
    rate: f64,
    capacity: f64,
}

impl TokenBucket {
    pub fn new(rate: f64, capacity: f64) -> Self {
        Self {
            tokens: capacity,
            last_update: std::time::Instant::now(),
            rate,
            capacity,
        }
    }

    pub async fn acquire(&mut self, tokens: f64) {
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(self.last_update).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.rate).min(self.capacity);
        self.last_update = now;

        if self.tokens >= tokens {
            self.tokens -= tokens;
        } else {
            let wait_time = (tokens - self.tokens) / self.rate;
            tokio::time::sleep(tokio::time::Duration::from_secs_f64(wait_time)).await;
            self.tokens = 0.0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_migration_source_from_str() {
        assert_eq!(
            MigrationSource::from_str("auth0").unwrap(),
            MigrationSource::Auth0
        );
        assert_eq!(
            MigrationSource::from_str("firebase").unwrap(),
            MigrationSource::Firebase
        );
        assert!(MigrationSource::from_str("unknown").is_err());
    }

    #[test]
    fn test_migration_status_is_terminal() {
        assert!(MigrationStatus::Completed.is_terminal());
        assert!(MigrationStatus::Failed.is_terminal());
        assert!(MigrationStatus::Cancelled.is_terminal());
        assert!(!MigrationStatus::Running.is_terminal());
        assert!(!MigrationStatus::Pending.is_terminal());
    }

    #[test]
    fn test_external_user_primary_identifier() {
        let user = ExternalUser {
            external_id: "auth0|123".to_string(),
            email: Some("test@example.com".to_string()),
            ..Default::default()
        };
        assert_eq!(user.primary_identifier(), "test@example.com");

        let user2 = ExternalUser {
            external_id: "auth0|123".to_string(),
            username: Some("testuser".to_string()),
            ..Default::default()
        };
        assert_eq!(user2.primary_identifier(), "testuser");
    }

    #[test]
    fn test_migration_result_success_rate() {
        let mut result = MigrationResult::new("test".to_string(), false);
        result.total = 100;
        result.migrated = 75;
        result.failed = 25;
        assert_eq!(result.success_rate(), 75.0);
    }
}
