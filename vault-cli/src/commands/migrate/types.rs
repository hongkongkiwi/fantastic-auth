//! Shared types for migration commands

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

/// Migration error types
#[derive(Error, Debug)]
pub enum MigrationError {
    #[error("API error: {0}")]
    ApiError(String),
    
    #[error("Authentication failed: {0}")]
    AuthenticationError(String),
    
    #[error("Rate limit exceeded")]
    RateLimitExceeded,
    
    #[error("Validation error: {0}")]
    ValidationError(String),
    
    #[error("Network error: {0}")]
    NetworkError(String),
    
    #[error("Parse error: {0}")]
    ParseError(String),
    
    #[error("Import error: {0}")]
    ImportError(String),
    
    #[error("Conflict: {0}")]
    Conflict(String),
    
    #[error("Not found: {0}")]
    NotFound(String),
    
    #[error("Other error: {0}")]
    Other(String),
}

impl From<anyhow::Error> for MigrationError {
    fn from(err: anyhow::Error) -> Self {
        let err_str = err.to_string();
        if err_str.contains("already exists") {
            MigrationError::Conflict(err_str)
        } else if err_str.contains("not found") {
            MigrationError::NotFound(err_str)
        } else if err_str.contains("authentication") || err_str.contains("unauthorized") {
            MigrationError::AuthenticationError(err_str)
        } else if err_str.contains("rate limit") {
            MigrationError::RateLimitExceeded
        } else {
            MigrationError::Other(err_str)
        }
    }
}

impl From<reqwest::Error> for MigrationError {
    fn from(err: reqwest::Error) -> Self {
        MigrationError::NetworkError(err.to_string())
    }
}

/// Migration report summarizing the results
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MigrationReport {
    /// Total number of users processed
    pub total_count: usize,
    /// Number of users successfully migrated
    pub success_count: usize,
    /// Number of users that failed to migrate
    pub failure_count: usize,
    /// Number of users skipped (e.g., already exist)
    pub skipped_count: usize,
    /// Detailed failures with reasons
    pub failures: Vec<MigrationFailure>,
    /// Warnings generated during migration
    pub warnings: Vec<String>,
    /// Duration of the migration
    pub duration_secs: u64,
}

impl MigrationReport {
    pub fn new() -> Self {
        Self::default()
    }
    
    pub fn add_success(&mut self) {
        self.success_count += 1;
        self.total_count += 1;
    }
    
    pub fn add_failure(&mut self, email: String, reason: String) {
        self.failures.push(MigrationFailure { email, reason });
        self.failure_count += 1;
        self.total_count += 1;
    }
    
    pub fn add_skipped(&mut self) {
        self.skipped_count += 1;
        self.total_count += 1;
    }
    
    pub fn add_warning(&mut self, warning: String) {
        self.warnings.push(warning);
    }
    
    pub fn print_summary(&self) {
        println!("\n📊 Migration Report");
        println!("═══════════════════════════════════════");
        println!("✅ Successfully migrated: {}", self.success_count);
        println!("⏭️  Skipped (already exist): {}", self.skipped_count);
        println!("❌ Failed: {}", self.failure_count);
        println!("📦 Total processed: {}", self.total_count);
        println!("⏱️  Duration: {}s", self.duration_secs);
        
        if !self.warnings.is_empty() {
            println!("\n⚠️  Warnings ({}):", self.warnings.len());
            for warning in &self.warnings {
                println!("   • {}", warning);
            }
        }
        
        if !self.failures.is_empty() {
            println!("\n❌ Failures ({}):", self.failures.len());
            for failure in self.failures.iter().take(10) {
                println!("   • {}: {}", failure.email, failure.reason);
            }
            if self.failures.len() > 10 {
                println!("   ... and {} more", self.failures.len() - 10);
            }
        }
        println!("═══════════════════════════════════════");
    }
}

/// Details about a failed migration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationFailure {
    pub email: String,
    pub reason: String,
}

/// Preview of what would be migrated (for dry-run mode)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MigrationPreview {
    pub user_count: usize,
    pub organization_count: usize,
    pub sample_users: Vec<PreviewUser>,
    pub estimated_time_secs: u64,
}

/// Preview user for dry-run display
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreviewUser {
    pub email: String,
    pub name: Option<String>,
    pub source_id: String,
}

/// Conflict resolution strategy
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ConflictStrategy {
    /// Skip the conflicting user
    #[default]
    Skip,
    /// Update the existing user with new data
    Update,
    /// Merge data (keep existing values, add new ones)
    Merge,
    /// Fail the entire migration
    Fail,
}

impl std::str::FromStr for ConflictStrategy {
    type Err = String;
    
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "skip" => Ok(ConflictStrategy::Skip),
            "update" => Ok(ConflictStrategy::Update),
            "merge" => Ok(ConflictStrategy::Merge),
            "fail" => Ok(ConflictStrategy::Fail),
            _ => Err(format!("Unknown conflict strategy: {}", s)),
        }
    }
}

/// Import format for generic imports
#[derive(Clone, Copy, Debug, Default)]
pub enum ImportFormat {
    #[default]
    Csv,
    Json,
}

/// Export format for exports
#[derive(Clone, Copy, Debug, Default)]
pub enum ExportFormat {
    #[default]
    Csv,
    Json,
    Yaml,
}

/// Common user data structure used across migrations
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ImportUser {
    pub email: String,
    pub name: Option<String>,
    #[serde(rename = "emailVerified")]
    pub email_verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<HashMap<String, serde_json::Value>>,
    /// Social/provider identities
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identities: Option<Vec<UserIdentity>>,
}

/// User identity for social/login providers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserIdentity {
    pub provider: String,
    pub provider_user_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

/// Organization data for migration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportOrganization {
    pub name: String,
    pub slug: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<HashMap<String, serde_json::Value>>,
    pub members: Vec<OrgMember>,
}

/// Organization member
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgMember {
    pub email: String,
    pub role: String,
}

/// Trait for all migration implementations
#[async_trait::async_trait]
pub trait Migrator: Send + Sync {
    /// Get a preview of what would be migrated
    async fn preview(&self) -> Result<MigrationPreview, MigrationError>;
    
    /// Execute the migration
    async fn migrate(&mut self) -> Result<MigrationReport, MigrationError>;
    
    /// Validate the migration configuration
    async fn validate(&self) -> Result<(), MigrationError>;
}

/// Progress callback for migration updates
pub type ProgressCallback = Box<dyn Fn(usize, usize) + Send + Sync>;

/// Migration configuration options
#[derive(Default)]
pub struct MigrationOptions {
    /// Dry run mode (no actual changes)
    pub dry_run: bool,
    /// Batch size for processing
    pub batch_size: usize,
    /// Conflict resolution strategy
    pub conflict_strategy: ConflictStrategy,
    /// Include/exclude specific fields
    pub include_fields: Option<Vec<String>>,
    pub exclude_fields: Option<Vec<String>>,
    /// Transform function for user data
    pub transform: Option<fn(ImportUser) -> ImportUser>,
    /// Progress callback
    pub on_progress: Option<ProgressCallback>,
    /// Resume from a specific offset
    pub resume_offset: Option<usize>,
}

impl std::fmt::Debug for MigrationOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MigrationOptions")
            .field("dry_run", &self.dry_run)
            .field("batch_size", &self.batch_size)
            .field("conflict_strategy", &self.conflict_strategy)
            .field("include_fields", &self.include_fields)
            .field("exclude_fields", &self.exclude_fields)
            .field("transform", &self.transform.is_some())
            .field("on_progress", &self.on_progress.is_some())
            .field("resume_offset", &self.resume_offset)
            .finish()
    }
}

impl Clone for MigrationOptions {
    fn clone(&self) -> Self {
        Self {
            dry_run: self.dry_run,
            batch_size: self.batch_size,
            conflict_strategy: self.conflict_strategy,
            include_fields: self.include_fields.clone(),
            exclude_fields: self.exclude_fields.clone(),
            transform: self.transform,
            on_progress: None, // Callbacks cannot be cloned
            resume_offset: self.resume_offset,
        }
    }
}

impl MigrationOptions {
    pub fn new() -> Self {
        Self {
            batch_size: 100,
            ..Default::default()
        }
    }
    
    pub fn with_dry_run(mut self, dry_run: bool) -> Self {
        self.dry_run = dry_run;
        self
    }
    
    pub fn with_batch_size(mut self, batch_size: usize) -> Self {
        self.batch_size = batch_size;
        self
    }
    
    pub fn with_conflict_strategy(mut self, strategy: ConflictStrategy) -> Self {
        self.conflict_strategy = strategy;
        self
    }
}

/// Migration state for resumable migrations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationState {
    pub source: String,
    pub started_at: String,
    pub last_offset: usize,
    pub processed_emails: Vec<String>,
    pub failed_emails: Vec<String>,
}

impl MigrationState {
    pub fn new(source: impl Into<String>) -> Self {
        Self {
            source: source.into(),
            started_at: chrono::Utc::now().to_rfc3339(),
            last_offset: 0,
            processed_emails: Vec::new(),
            failed_emails: Vec::new(),
        }
    }
}
