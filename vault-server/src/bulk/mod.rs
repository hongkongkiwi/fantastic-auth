//! Bulk user operations module
//!
//! Provides import/export functionality for user management at scale.
//! Supports CSV and JSON formats with async processing, progress tracking,
//! and detailed error reporting.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;

pub mod export;
pub mod import;

/// Unique identifier for bulk jobs
pub type JobId = Uuid;

/// Type of bulk operation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "VARCHAR", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum JobType {
    /// Import users from file
    Import,
    /// Export users to file
    Export,
}

/// Status of a bulk job
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "VARCHAR", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    /// Job is queued and waiting to be processed
    Pending,
    /// Job is currently being processed
    Processing,
    /// Job completed successfully (may have partial errors)
    Completed,
    /// Job failed entirely
    Failed,
    /// Job was cancelled by user
    Cancelled,
}

/// File format for import/export
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "VARCHAR", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum FileFormat {
    /// CSV format
    Csv,
    /// JSON format
    Json,
}

impl std::fmt::Display for FileFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FileFormat::Csv => write!(f, "csv"),
            FileFormat::Json => write!(f, "json"),
        }
    }
}

impl std::str::FromStr for FileFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "csv" => Ok(FileFormat::Csv),
            "json" => Ok(FileFormat::Json),
            _ => Err(format!("Unknown file format: {}", s)),
        }
    }
}

/// A bulk import job
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkImportJob {
    /// Unique job ID
    pub id: JobId,
    /// Tenant ID
    pub tenant_id: String,
    /// Current status
    pub status: JobStatus,
    /// File format
    pub format: FileFormat,
    /// Total records to process
    pub total_records: usize,
    /// Records processed so far
    pub processed_records: usize,
    /// Successfully imported records
    pub success_count: usize,
    /// Failed records
    pub error_count: usize,
    /// Path to uploaded import file
    pub file_path: Option<PathBuf>,
    /// Path to error report (if any errors)
    pub error_report_path: Option<PathBuf>,
    /// User who created the job
    pub created_by: String,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// When processing started
    pub started_at: Option<DateTime<Utc>>,
    /// When processing completed
    pub completed_at: Option<DateTime<Utc>>,
    /// Import options
    pub options: ImportOptions,
    /// Error message (if job failed)
    pub error_message: Option<String>,
}

/// A bulk export job
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkExportJob {
    /// Unique job ID
    pub id: JobId,
    /// Tenant ID
    pub tenant_id: String,
    /// Current status
    pub status: JobStatus,
    /// File format
    pub format: FileFormat,
    /// Total records to export
    pub total_records: usize,
    /// Records processed so far
    pub processed_records: usize,
    /// Path to result file
    pub result_file_path: Option<PathBuf>,
    /// User who created the job
    pub created_by: String,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// When processing started
    pub started_at: Option<DateTime<Utc>>,
    /// When processing completed
    pub completed_at: Option<DateTime<Utc>>,
    /// Export options
    pub options: ExportOptions,
    /// Error message (if job failed)
    pub error_message: Option<String>,
}

/// Options for import operations
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ImportOptions {
    /// Continue processing on individual record errors
    #[serde(default = "default_continue_on_error")]
    pub continue_on_error: bool,
    /// Preview mode - validate without importing
    #[serde(default)]
    pub preview_mode: bool,
    /// Default password for imported users (if not specified)
    pub default_password: Option<String>,
    /// Auto-generate passwords
    #[serde(default)]
    pub auto_generate_password: bool,
    /// Send welcome emails
    #[serde(default)]
    pub send_welcome_email: bool,
    /// Skip existing users (by email)
    #[serde(default)]
    pub skip_existing: bool,
    /// Update existing users instead of skipping
    #[serde(default)]
    pub update_existing: bool,
    /// Organization ID to add users to
    pub organization_id: Option<String>,
    /// Default role for imported users
    #[serde(default = "default_role")]
    pub default_role: String,
}

fn default_continue_on_error() -> bool {
    true
}

fn default_role() -> String {
    "member".to_string()
}

/// Options for export operations
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExportOptions {
    /// Filter by user status
    pub status_filter: Option<Vec<String>>,
    /// Filter by organization ID
    pub organization_id: Option<String>,
    /// Include only users created after this date
    pub created_after: Option<DateTime<Utc>>,
    /// Include only users created before this date
    pub created_before: Option<DateTime<Utc>>,
    /// Include specific fields (empty = all)
    pub include_fields: Vec<String>,
    /// Exclude specific fields
    pub exclude_fields: Vec<String>,
    /// Include password hashes (security risk!)
    #[serde(default)]
    pub include_password_hashes: bool,
    /// Maximum records to export (0 = unlimited)
    #[serde(default)]
    pub max_records: usize,
}

/// Result of a bulk operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkResult {
    /// Total records processed
    pub total: usize,
    /// Successfully processed
    pub success: usize,
    /// Failed records
    pub failed: usize,
    /// Processing time in milliseconds
    pub duration_ms: u64,
}

/// A single user import record (CSV/JSON row)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UserImportRecord {
    /// Email address (required)
    pub email: String,
    /// Full name
    pub name: Option<String>,
    /// User role
    pub role: Option<String>,
    /// Organization ID to add user to
    pub organization_id: Option<String>,
    /// Password (or "AutoGenerate" for auto-generated)
    pub password: Option<String>,
    /// Whether email is verified
    #[serde(default)]
    pub email_verified: bool,
    /// User status
    #[serde(default = "default_import_status")]
    pub status: String,
    /// Phone number
    pub phone_number: Option<String>,
    /// Additional metadata (JSON)
    #[serde(flatten)]
    pub extra_fields: std::collections::HashMap<String, serde_json::Value>,
}

fn default_import_status() -> String {
    "active".to_string()
}

/// A single user export record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserExportRecord {
    /// User ID
    pub id: String,
    /// Email address
    pub email: String,
    /// Full name
    pub name: Option<String>,
    /// User status
    pub status: String,
    /// Whether email is verified
    pub email_verified: bool,
    /// Role in organization (if specified)
    pub role: Option<String>,
    /// Organization ID
    pub organization_id: Option<String>,
    /// Phone number
    pub phone_number: Option<String>,
    /// MFA enabled
    pub mfa_enabled: bool,
    /// Last login timestamp
    pub last_login_at: Option<DateTime<Utc>>,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
    /// Updated timestamp
    pub updated_at: DateTime<Utc>,
}

/// Import error for a single record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportError {
    /// Row number in the import file
    pub row_number: usize,
    /// Email of the user that failed
    pub email: String,
    /// Error message
    pub error: String,
    /// Field that caused the error (if applicable)
    pub field: Option<String>,
}

/// Progress update for long-running jobs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobProgress {
    /// Job ID
    pub job_id: JobId,
    /// Current status
    pub status: JobStatus,
    /// Total records
    pub total: usize,
    /// Processed so far
    pub processed: usize,
    /// Successfully processed
    pub success: usize,
    /// Failed records
    pub failed: usize,
    /// Percentage complete (0-100)
    pub percentage: u8,
    /// Estimated time remaining in seconds
    pub eta_seconds: Option<u64>,
}

impl JobProgress {
    /// Calculate progress percentage
    pub fn calculate(total: usize, processed: usize) -> u8 {
        if total == 0 {
            return 0;
        }
        ((processed as f64 / total as f64) * 100.0) as u8
    }

    /// Create a progress update from a job
    pub fn from_import_job(job: &BulkImportJob) -> Self {
        let percentage = Self::calculate(job.total_records, job.processed_records);

        // Calculate ETA based on average processing time
        let eta_seconds = if job.processed_records > 0 && job.started_at.is_some() {
            let elapsed = Utc::now() - job.started_at.unwrap();
            let avg_time_per_record = elapsed.num_seconds() as f64 / job.processed_records as f64;
            let remaining = job.total_records - job.processed_records;
            Some((avg_time_per_record * remaining as f64) as u64)
        } else {
            None
        };

        Self {
            job_id: job.id,
            status: job.status,
            total: job.total_records,
            processed: job.processed_records,
            success: job.success_count,
            failed: job.error_count,
            percentage,
            eta_seconds,
        }
    }
}

/// Database row for bulk jobs
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct BulkJobRow {
    pub id: uuid::Uuid,
    pub tenant_id: uuid::Uuid,
    pub job_type: String,
    pub status: String,
    pub format: String,
    pub total_records: i32,
    pub processed_records: i32,
    pub success_count: i32,
    pub error_count: i32,
    pub file_path: Option<String>,
    pub error_report_path: Option<String>,
    pub result_file_path: Option<String>,
    pub options: serde_json::Value,
    pub error_message: Option<String>,
    pub created_by: uuid::Uuid,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
}

/// Storage configuration for bulk files
#[derive(Debug, Clone)]
pub struct StorageConfig {
    /// Root directory for storing bulk operation files
    pub root_path: PathBuf,
    /// Maximum file size in bytes (default: 100MB)
    pub max_file_size: usize,
    /// Maximum age for completed job files (for cleanup)
    pub max_file_age_days: u32,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            root_path: PathBuf::from("./data/bulk"),
            max_file_size: 100 * 1024 * 1024, // 100MB
            max_file_age_days: 7,
        }
    }
}

impl StorageConfig {
    /// Create storage config from environment
    pub fn from_env() -> Self {
        let root_path = std::env::var("BULK_STORAGE_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("./data/bulk"));

        let max_file_size = std::env::var("BULK_MAX_FILE_SIZE")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(100 * 1024 * 1024);

        let max_file_age_days = std::env::var("BULK_MAX_FILE_AGE_DAYS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(7);

        Self {
            root_path,
            max_file_size,
            max_file_age_days,
        }
    }

    /// Get path for a job's upload file
    pub fn upload_path(&self, job_id: JobId) -> PathBuf {
        self.root_path
            .join("uploads")
            .join(format!("{}.tmp", job_id))
    }

    /// Get path for a job's result file
    pub fn result_path(&self, job_id: JobId, format: FileFormat) -> PathBuf {
        self.root_path.join("results").join(format!(
            "{}.{}.{}",
            job_id,
            format,
            if format == FileFormat::Csv {
                "csv"
            } else {
                "json"
            }
        ))
    }

    /// Get path for a job's error report
    pub fn error_report_path(&self, job_id: JobId) -> PathBuf {
        self.root_path
            .join("errors")
            .join(format!("{}_errors.json", job_id))
    }

    /// Ensure directories exist
    pub async fn ensure_dirs(&self) -> std::io::Result<()> {
        tokio::fs::create_dir_all(self.root_path.join("uploads")).await?;
        tokio::fs::create_dir_all(self.root_path.join("results")).await?;
        tokio::fs::create_dir_all(self.root_path.join("errors")).await?;
        Ok(())
    }
}
