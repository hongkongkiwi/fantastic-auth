//! Bulk user import functionality
//!
//! Provides CSV and JSON parsing, validation, and batch insertion
//! with progress tracking, error collection, and adaptive rate limiting.

use crate::bulk::{
    BulkImportJob, FileFormat, ImportError, JobStatus, StorageConfig,
    UserImportRecord,
};
use crate::db::Database;
use std::collections::HashMap;
use std::io::Cursor;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::time::{sleep, Duration, Instant};
use tracing::{debug, error, info, warn};
use uuid::Uuid;
use vault_core::email::{EmailRequest, EmailService};
use vault_core::models::user::UserStatus;

/// Default batch size for processing
const DEFAULT_BATCH_SIZE: usize = 100;
/// Minimum delay between batches (milliseconds)
const MIN_DELAY_MS: u64 = 1;
/// Maximum delay between batches (milliseconds)
const MAX_DELAY_MS: u64 = 1000;
/// Target processing time per batch (milliseconds)
const TARGET_BATCH_TIME_MS: u64 = 500;
/// Error rate threshold for circuit breaker (0.0 - 1.0)
const ERROR_RATE_THRESHOLD: f64 = 0.3;
/// Consecutive errors threshold for circuit breaker
const CONSECUTIVE_ERRORS_THRESHOLD: usize = 5;

/// CSV header for import template
pub const CSV_TEMPLATE_HEADER: &str =
    "email,name,role,organization_id,password,email_verified,status,phone_number\n";

/// JSON template for import
pub const JSON_TEMPLATE: &str = r#"[
  {
    "email": "user1@example.com",
    "name": "John Doe",
    "role": "member",
    "organization_id": "org-123",
    "password": "AutoGenerate",
    "email_verified": true,
    "status": "active",
    "phone_number": "+1-555-0123"
  }
]"#;

/// Adaptive rate limiter for bulk imports
/// 
/// Automatically adjusts the delay between batches based on:
/// - Processing time per batch
/// - Error rates
/// - Consecutive errors (circuit breaker pattern)
#[derive(Debug)]
pub struct AdaptiveRateLimiter {
    /// Current delay between batches (milliseconds)
    current_delay_ms: AtomicUsize,
    /// Consecutive error counter
    consecutive_errors: AtomicUsize,
    /// Success counter for the current window
    success_count: AtomicUsize,
    /// Error counter for the current window
    error_count: AtomicUsize,
    /// Last batch processing time
    last_batch_time_ms: AtomicUsize,
}

impl AdaptiveRateLimiter {
    /// Create a new adaptive rate limiter
    pub fn new() -> Self {
        Self {
            current_delay_ms: AtomicUsize::new(10), // Start with 10ms delay
            consecutive_errors: AtomicUsize::new(0),
            success_count: AtomicUsize::new(0),
            error_count: AtomicUsize::new(0),
            last_batch_time_ms: AtomicUsize::new(0),
        }
    }
    
    /// Record a successful batch processing
    pub fn record_success(&self, batch_time_ms: u64) {
        self.consecutive_errors.store(0, Ordering::SeqCst);
        self.success_count.fetch_add(1, Ordering::SeqCst);
        self.last_batch_time_ms.store(batch_time_ms as usize, Ordering::SeqCst);
        
        // Decrease delay if processing is fast
        if batch_time_ms < TARGET_BATCH_TIME_MS / 2 {
            self.adjust_delay(-2); // Decrease by 2ms
        } else if batch_time_ms < TARGET_BATCH_TIME_MS {
            self.adjust_delay(-1); // Decrease by 1ms
        }
    }
    
    /// Record a failed batch processing
    pub fn record_error(&self) {
        self.consecutive_errors.fetch_add(1, Ordering::SeqCst);
        self.error_count.fetch_add(1, Ordering::SeqCst);
        
        // Increase delay on error (exponential backoff)
        let consecutive = self.consecutive_errors.load(Ordering::SeqCst);
        let increase = (2usize.pow(consecutive.min(5) as u32)).min(100);
        self.adjust_delay(increase as i64);
    }
    
    /// Check if circuit breaker is open (too many consecutive errors)
    pub fn is_circuit_open(&self) -> bool {
        let consecutive = self.consecutive_errors.load(Ordering::SeqCst);
        let errors = self.error_count.load(Ordering::SeqCst);
        let successes = self.success_count.load(Ordering::SeqCst);
        let total = errors + successes;
        
        // Circuit opens on too many consecutive errors OR high error rate
        if consecutive >= CONSECUTIVE_ERRORS_THRESHOLD {
            return true;
        }
        
        if total > 10 {
            let error_rate = errors as f64 / total as f64;
            if error_rate > ERROR_RATE_THRESHOLD {
                return true;
            }
        }
        
        false
    }
    
    /// Get current delay
    pub fn current_delay(&self) -> Duration {
        let ms = self.current_delay_ms.load(Ordering::SeqCst) as u64;
        Duration::from_millis(ms.clamp(MIN_DELAY_MS, MAX_DELAY_MS))
    }
    
    /// Adjust delay by delta (positive = increase, negative = decrease)
    fn adjust_delay(&self, delta: i64) {
        let current = self.current_delay_ms.load(Ordering::SeqCst) as i64;
        let new_delay = (current + delta).clamp(MIN_DELAY_MS as i64, MAX_DELAY_MS as i64);
        self.current_delay_ms.store(new_delay as usize, Ordering::SeqCst);
    }
    
    /// Reset circuit breaker
    pub fn reset(&self) {
        self.consecutive_errors.store(0, Ordering::SeqCst);
        self.success_count.store(0, Ordering::SeqCst);
        self.error_count.store(0, Ordering::SeqCst);
    }
    
    /// Get current statistics
    pub fn stats(&self) -> RateLimiterStats {
        RateLimiterStats {
            current_delay_ms: self.current_delay_ms.load(Ordering::SeqCst) as u64,
            consecutive_errors: self.consecutive_errors.load(Ordering::SeqCst),
            success_count: self.success_count.load(Ordering::SeqCst),
            error_count: self.error_count.load(Ordering::SeqCst),
            circuit_open: self.is_circuit_open(),
        }
    }
}

impl Default for AdaptiveRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

/// Rate limiter statistics
#[derive(Debug, Clone)]
pub struct RateLimiterStats {
    pub current_delay_ms: u64,
    pub consecutive_errors: usize,
    pub success_count: usize,
    pub error_count: usize,
    pub circuit_open: bool,
}

/// Result of parsing an import file
#[derive(Debug, Clone)]
pub struct ParseResult {
    /// Total records parsed
    pub total: usize,
    /// Successfully parsed records
    pub records: Vec<(usize, UserImportRecord)>,
    /// Parse errors
    pub errors: Vec<ImportError>,
}

/// Parse a CSV import file
pub fn parse_csv(data: &[u8]) -> anyhow::Result<ParseResult> {
    let mut records = Vec::new();
    let mut errors = Vec::new();
    let mut total = 0;

    // Convert bytes to string
    let content = String::from_utf8_lossy(data);
    let cursor = Cursor::new(content.as_ref());

    let mut csv_reader = csv::ReaderBuilder::new()
        .has_headers(true)
        .trim(csv::Trim::All)
        .from_reader(cursor);

    // Get headers for flexible parsing
    let headers = csv_reader.headers()?.clone();

    // Track row number (starting from 2, as 1 is header)
    let mut row_number = 1;

    for result in csv_reader.records() {
        row_number += 1;
        total += 1;

        match result {
            Ok(csv_record) => match parse_csv_row(&headers, &csv_record, row_number) {
                Ok(record) => {
                    records.push((row_number, record));
                }
                Err(e) => {
                    errors.push(ImportError {
                        row_number,
                        email: csv_record.get(0).unwrap_or("unknown").to_string(),
                        error: e,
                        field: None,
                    });
                }
            },
            Err(e) => {
                errors.push(ImportError {
                    row_number,
                    email: String::new(),
                    error: format!("CSV parse error: {}", e),
                    field: None,
                });
            }
        }
    }

    Ok(ParseResult {
        total,
        records,
        errors,
    })
}

/// Parse a single CSV row into UserImportRecord
fn parse_csv_row(
    headers: &csv::StringRecord,
    record: &csv::StringRecord,
    row_number: usize,
) -> Result<UserImportRecord, String> {
    if record.len() < 1 {
        return Err("Empty row".to_string());
    }

    let mut email = String::new();
    let mut name = None;
    let mut role = None;
    let mut organization_id = None;
    let mut password = None;
    let mut email_verified = false;
    let mut status = Some("active".to_string());
    let mut phone_number = None;
    let mut extra_fields = std::collections::HashMap::new();

    // Map columns by header name
    for (i, header) in headers.iter().enumerate() {
        let value = record.get(i).unwrap_or("").trim();

        match header.to_lowercase().as_str() {
            "email" => email = value.to_string(),
            "name" => {
                if !value.is_empty() {
                    name = Some(value.to_string());
                }
            }
            "role" => {
                if !value.is_empty() {
                    role = Some(value.to_string());
                }
            }
            "organization_id" | "organization" | "org_id" => {
                if !value.is_empty() {
                    organization_id = Some(value.to_string());
                }
            }
            "password" | "passwd" => {
                if !value.is_empty() {
                    password = Some(value.to_string());
                }
            }
            "email_verified" | "verified" => {
                email_verified =
                    matches!(value.to_lowercase().as_str(), "true" | "1" | "yes" | "y");
            }
            "status" => {
                if !value.is_empty() {
                    status = Some(value.to_string());
                }
            }
            "phone_number" | "phone" | "telephone" => {
                if !value.is_empty() {
                    phone_number = Some(value.to_string());
                }
            }
            // Store unknown fields as extra metadata
            _ => {
                if !value.is_empty() {
                    extra_fields.insert(header.to_string(), serde_json::json!(value));
                }
            }
        }
    }

    // Validate required fields
    if email.is_empty() {
        return Err(format!("Row {}: Email is required", row_number));
    }

    // Validate email format
    if !is_valid_email(&email) {
        return Err(format!(
            "Row {}: Invalid email format: {}",
            row_number, email
        ));
    }

    Ok(UserImportRecord {
        email,
        name,
        role,
        organization_id,
        password,
        email_verified,
        status: status.unwrap_or_else(|| "active".to_string()),
        phone_number,
        extra_fields,
    })
}

/// Parse a JSON import file
pub fn parse_json(data: &[u8]) -> anyhow::Result<ParseResult> {
    let mut records = Vec::new();
    let mut errors = Vec::new();
    let mut total = 0;

    // Try to parse as array first
    let parsed: Result<Vec<serde_json::Value>, _> = serde_json::from_slice(data);

    let items = match parsed {
        Ok(array) => array,
        Err(_) => {
            // Try as single object
            match serde_json::from_slice::<serde_json::Value>(data) {
                Ok(obj) => vec![obj],
                Err(e) => {
                    return Err(anyhow::anyhow!("Failed to parse JSON: {}", e));
                }
            }
        }
    };

    for (i, item) in items.into_iter().enumerate() {
        let row_number = i + 2; // +2 because row 1 is header/start
        total += 1;

        match serde_json::from_value::<UserImportRecord>(item.clone()) {
            Ok(record) => {
                // Validate email
                if record.email.is_empty() {
                    errors.push(ImportError {
                        row_number,
                        email: String::new(),
                        error: "Email is required".to_string(),
                        field: Some("email".to_string()),
                    });
                    continue;
                }

                if !is_valid_email(&record.email) {
                    errors.push(ImportError {
                        row_number,
                        email: record.email.clone(),
                        error: format!("Invalid email format: {}", record.email),
                        field: Some("email".to_string()),
                    });
                    continue;
                }

                records.push((row_number, record));
            }
            Err(e) => {
                let email = item
                    .get("email")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string();

                errors.push(ImportError {
                    row_number,
                    email,
                    error: format!("JSON parse error: {}", e),
                    field: None,
                });
            }
        }
    }

    Ok(ParseResult {
        total,
        records,
        errors,
    })
}

/// Parse import file based on format
pub fn parse_file(data: &[u8], format: FileFormat) -> anyhow::Result<ParseResult> {
    match format {
        FileFormat::Csv => parse_csv(data),
        FileFormat::Json => parse_json(data),
    }
}

/// Basic email validation
fn is_valid_email(email: &str) -> bool {
    // Basic email regex pattern
    let email_regex = regex::Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$");

    match email_regex {
        Ok(regex) => regex.is_match(email),
        Err(_) => {
            // Fallback to simple check
            email.contains('@') && email.contains('.')
        }
    }
}

/// Validate a user import record
pub fn validate_record(record: &UserImportRecord, row_number: usize) -> Result<(), ImportError> {
    // Validate email
    if record.email.is_empty() {
        return Err(ImportError {
            row_number,
            email: String::new(),
            error: "Email is required".to_string(),
            field: Some("email".to_string()),
        });
    }

    if !is_valid_email(&record.email) {
        return Err(ImportError {
            row_number,
            email: record.email.clone(),
            error: "Invalid email format".to_string(),
            field: Some("email".to_string()),
        });
    }

    // Validate password if provided and not auto-generate
    if let Some(ref pwd) = record.password {
        if pwd != "AutoGenerate" && pwd.len() < 8 {
            return Err(ImportError {
                row_number,
                email: record.email.clone(),
                error: "Password must be at least 8 characters".to_string(),
                field: Some("password".to_string()),
            });
        }
    }

    // Validate status
    let valid_statuses = ["pending", "active", "suspended", "deactivated"];
    if !valid_statuses.contains(&record.status.as_str()) {
        return Err(ImportError {
            row_number,
            email: record.email.clone(),
            error: format!(
                "Invalid status: {}. Must be one of: {:?}",
                record.status, valid_statuses
            ),
            field: Some("status".to_string()),
        });
    }

    Ok(())
}

/// Import processor for handling bulk imports
pub struct ImportProcessor {
    db: Database,
    storage_config: StorageConfig,
    email_service: Option<Arc<dyn EmailService>>,
}

impl ImportProcessor {
    /// Create a new import processor
    pub fn new(db: Database, storage_config: StorageConfig) -> Self {
        Self {
            db,
            storage_config,
            email_service: None,
        }
    }

    /// Attach email service for optional welcome emails
    pub fn with_email_service(mut self, email_service: Option<Arc<dyn EmailService>>) -> Self {
        self.email_service = email_service;
        self
    }

    /// Process an import job
    pub async fn process(&self, job: &mut BulkImportJob) -> anyhow::Result<()> {
        use crate::middleware::security::{validate_file_path, validate_file_size, FileOperation};

        info!(
            job_id = %job.id,
            tenant_id = %job.tenant_id,
            "Starting import job"
        );

        job.status = JobStatus::Processing;
        job.started_at = Some(chrono::Utc::now());

        // Read the import file
        let file_path = job
            .file_path
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No file path specified"))?;

        // SECURITY: Validate file path before reading
        let path_str = file_path.to_string_lossy();
        if let Some(filename) = file_path.file_name().and_then(|n| n.to_str()) {
            if !validate_file_path(filename) {
                anyhow::bail!("Invalid file path: security violation");
            }
        }

        // SECURITY: Check file size BEFORE reading to prevent OOM
        let metadata = tokio::fs::metadata(file_path).await?;
        let max_size = match job.format {
            super::FileFormat::Csv => FileOperation::CsvImport,
            super::FileFormat::Json => FileOperation::JsonImport,
        };
        if !validate_file_size(metadata.len() as usize, max_size) {
            anyhow::bail!("File size exceeds maximum allowed for this format");
        }

        let data = tokio::fs::read(file_path).await?;

        // Parse the file
        let parse_result = parse_file(&data, job.format)?;

        job.total_records = parse_result.total;
        job.processed_records = 0;
        job.success_count = 0;
        job.error_count = parse_result.errors.len();

        info!(
            job_id = %job.id,
            total = job.total_records,
            parse_errors = parse_result.errors.len(),
            "Parsed import file"
        );

        // If preview mode, just return the parse results
        if job.options.preview_mode {
            job.status = JobStatus::Completed;
            job.completed_at = Some(chrono::Utc::now());

            // Write errors to file
            if !parse_result.errors.is_empty() {
                self.write_error_report(job, &parse_result.errors).await?;
            }

            return Ok(());
        }

        // Process records with adaptive rate limiting
        let mut errors = parse_result.errors;
        let batch_size = DEFAULT_BATCH_SIZE;
        let rate_limiter = AdaptiveRateLimiter::new();
        
        // Log initial rate limiter state
        info!(
            job_id = %job.id,
            initial_delay_ms = rate_limiter.current_delay().as_millis() as u64,
            "Starting import with adaptive rate limiting"
        );

        for chunk in parse_result.records.chunks(batch_size) {
            // Check if circuit breaker is open
            if rate_limiter.is_circuit_open() {
                error!(
                    job_id = %job.id,
                    "Circuit breaker open - too many errors, stopping import"
                );
                job.status = JobStatus::Failed;
                job.error_message = Some(
                    "Import stopped due to high error rate. Please check database connectivity and retry.".to_string()
                );
                
                if !errors.is_empty() {
                    self.write_error_report(job, &errors).await?;
                }
                
                return Ok(());
            }
            
            let batch_start = Instant::now();
            let mut batch_errors = 0;

            for (row_number, record) in chunk {
                match self.import_user(job, record, *row_number).await {
                    Ok(_) => {
                        job.success_count += 1;
                    }
                    Err(e) => {
                        batch_errors += 1;
                        job.error_count += 1;
                        errors.push(ImportError {
                            row_number: *row_number,
                            email: record.email.clone(),
                            error: e.to_string(),
                            field: None,
                        });

                        if !job.options.continue_on_error {
                            job.status = JobStatus::Failed;
                            job.error_message =
                                Some(format!("Import stopped at row {}: {}", row_number, e));

                            if !errors.is_empty() {
                                self.write_error_report(job, &errors).await?;
                            }

                            return Ok(());
                        }
                    }
                }

                job.processed_records += 1;
            }
            
            // Calculate batch processing time
            let batch_time_ms = batch_start.elapsed().as_millis() as u64;
            
            // Update rate limiter based on batch results
            if batch_errors == 0 {
                rate_limiter.record_success(batch_time_ms);
            } else {
                rate_limiter.record_error();
            }
            
            // Adaptive delay between batches
            let delay = rate_limiter.current_delay();
            
            // Log rate limiter adjustments periodically (every 10 batches)
            if job.processed_records % (batch_size * 10) == 0 {
                let stats = rate_limiter.stats();
                debug!(
                    job_id = %job.id,
                    processed = job.processed_records,
                    delay_ms = stats.current_delay_ms,
                    success_count = stats.success_count,
                    error_count = stats.error_count,
                    circuit_open = stats.circuit_open,
                    "Import rate limiter status"
                );
            }
            
            sleep(delay).await;
        }
        
        // Log final rate limiter stats
        let final_stats = rate_limiter.stats();
        info!(
            job_id = %job.id,
            final_delay_ms = final_stats.current_delay_ms,
            total_successes = final_stats.success_count,
            total_errors = final_stats.error_count,
            "Import rate limiting completed"
        );

        // Write error report if there are errors
        if !errors.is_empty() {
            self.write_error_report(job, &errors).await?;
        }

        // Mark job as completed
        job.status = JobStatus::Completed;
        job.completed_at = Some(chrono::Utc::now());

        info!(
            job_id = %job.id,
            success = job.success_count,
            failed = job.error_count,
            "Import job completed"
        );

        Ok(())
    }

    /// Import a single user
    async fn import_user(
        &self,
        job: &BulkImportJob,
        record: &UserImportRecord,
        row_number: usize,
    ) -> anyhow::Result<()> {
        // Validate the record
        validate_record(record, row_number)
            .map_err(|e| anyhow::anyhow!("Validation failed: {}", e.error))?;

        // Check if user already exists
        let existing = self
            .db
            .users()
            .find_by_email(&job.tenant_id, &record.email)
            .await?;

        if let Some(mut user) = existing {
            if job.options.skip_existing {
                debug!(email = %record.email, "Skipping existing user");
                return Ok(());
            }

            if !job.options.update_existing {
                return Err(anyhow::anyhow!("User already exists: {}", record.email));
            }
            user.email_verified = record.email_verified;
            user.status = parse_user_status(&record.status)?;

            if let Some(ref name) = record.name {
                user.profile.name = Some(name.clone());
            }
            if let Some(ref phone) = record.phone_number {
                user.profile.phone_number = Some(phone.clone());
            }

            let user = self.db.users().update(&job.tenant_id, &user).await?;

            if let Some(password_hash) = self.resolve_password_hash(job, record)? {
                let now = chrono::Utc::now();
                sqlx::query(
                    r#"UPDATE users
                       SET password_hash = $1,
                           password_changed_at = $2,
                           updated_at = $2
                       WHERE tenant_id = $3::uuid AND id = $4::uuid"#,
                )
                .bind(password_hash)
                .bind(now)
                .bind(&job.tenant_id)
                .bind(&user.id)
                .execute(self.db.pool())
                .await?;
            }

            if let Some(ref org_id) = record
                .organization_id
                .clone()
                .or_else(|| job.options.organization_id.clone())
            {
                let role = record
                    .role
                    .as_ref()
                    .or_else(|| Some(&job.options.default_role))
                    .cloned()
                    .unwrap_or_else(|| "member".to_string());

                self.add_user_to_organization(&job.tenant_id, &user.id, org_id, &role)
                    .await?;
            }

            if job.options.send_welcome_email {
                self.send_welcome_email(&record.email, record.name.as_deref())
                    .await;
            }

            return Ok(());
        }

        let password_hash = self.resolve_password_hash(job, record)?;

        // Create profile
        let profile = if let Some(ref name) = record.name {
            serde_json::json!({
                "name": name,
                "phone_number": record.phone_number,
            })
        } else {
            serde_json::json!({
                "phone_number": record.phone_number,
            })
        };

        // Create user
        let create_req = vault_core::db::users::CreateUserRequest {
            tenant_id: job.tenant_id.clone(),
            email: record.email.clone(),
            password_hash,
            email_verified: record.email_verified,
            profile: Some(profile),
            metadata: if record.extra_fields.is_empty() {
                None
            } else {
                Some(serde_json::to_value(&record.extra_fields)?)
            },
        };

        let user = self.db.users().create(create_req).await?;

        // Add to organization if specified
        if let Some(ref org_id) = record
            .organization_id
            .clone()
            .or_else(|| job.options.organization_id.clone())
        {
            let role = record
                .role
                .as_ref()
                .or_else(|| Some(&job.options.default_role))
                .cloned()
                .unwrap_or_else(|| "member".to_string());

            self.add_user_to_organization(&job.tenant_id, &user.id, org_id, &role)
                .await?;
        }

        if job.options.send_welcome_email {
            self.send_welcome_email(&record.email, record.name.as_deref())
                .await;
        }

        debug!(email = %record.email, user_id = %user.id, "Imported user");

        Ok(())
    }

    /// Add user to organization
    async fn add_user_to_organization(
        &self,
        tenant_id: &str,
        user_id: &str,
        org_id: &str,
        role: &str,
    ) -> anyhow::Result<()> {
        // Check if organization exists
        let org = self
            .db
            .organizations()
            .get_by_id(tenant_id, org_id)
            .await?;

        if org.is_none() {
            return Err(anyhow::anyhow!("Organization not found: {}", org_id));
        }

        // Check if membership already exists
        let existing = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM organization_members 
             WHERE tenant_id = $1::uuid AND organization_id = $2::uuid AND user_id = $3::uuid",
        )
        .bind(tenant_id)
        .bind(org_id)
        .bind(user_id)
        .fetch_one(self.db.pool())
        .await?;

        if existing > 0 {
            return Ok(()); // Already a member
        }

        // Create membership
        let membership_id = Uuid::new_v4().to_string();
        let now = chrono::Utc::now();

        sqlx::query(
            "INSERT INTO organization_members 
             (id, tenant_id, organization_id, user_id, role, status, joined_at, created_at, updated_at)
             VALUES ($1, $2::uuid, $3::uuid, $4::uuid, $5::org_role, 'active', $6, $6, $6)"
        )
        .bind(&membership_id)
        .bind(tenant_id)
        .bind(org_id)
        .bind(user_id)
        .bind(role)
        .bind(now)
        .execute(self.db.pool())
        .await?;

        Ok(())
    }

    /// Write error report to file
    async fn write_error_report(
        &self,
        job: &BulkImportJob,
        errors: &[ImportError],
    ) -> anyhow::Result<()> {
        let error_path = self.storage_config.error_report_path(job.id);

        // Ensure parent directory exists
        if let Some(parent) = error_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        let error_report = serde_json::json!({
            "job_id": job.id,
            "tenant_id": job.tenant_id,
            "total_errors": errors.len(),
            "errors": errors,
        });

        let content = serde_json::to_string_pretty(&error_report)?;
        tokio::fs::write(&error_path, content).await?;

        info!(
            job_id = %job.id,
            path = %error_path.display(),
            error_count = errors.len(),
            "Error report written"
        );

        Ok(())
    }

    fn resolve_password_hash(
        &self,
        job: &BulkImportJob,
        record: &UserImportRecord,
    ) -> anyhow::Result<Option<String>> {
        use vault_core::crypto::VaultPasswordHasher;

        if let Some(ref pwd) = record.password {
            if pwd == "AutoGenerate" {
                let generated = generate_temporary_password();
                return Ok(Some(VaultPasswordHasher::hash(&generated)?));
            }
            return Ok(Some(VaultPasswordHasher::hash(pwd)?));
        }

        if job.options.auto_generate_password {
            let generated = generate_temporary_password();
            return Ok(Some(VaultPasswordHasher::hash(&generated)?));
        }

        if let Some(ref default_pwd) = job.options.default_password {
            return Ok(Some(VaultPasswordHasher::hash(default_pwd)?));
        }

        Ok(None)
    }

    async fn send_welcome_email(&self, email: &str, name: Option<&str>) {
        let Some(service) = &self.email_service else {
            debug!(email = %email, "Welcome email requested but email service is not configured");
            return;
        };

        let display_name = name.unwrap_or("there");
        let request = EmailRequest {
            to: email.to_string(),
            to_name: name.map(ToString::to_string),
            subject: "Welcome to FantasticAuth".to_string(),
            html_body: format!(
                "<p>Hello {},</p><p>Your account is ready. You can sign in now.</p>",
                display_name
            ),
            text_body: format!(
                "Hello {},\n\nYour account is ready. You can sign in now.",
                display_name
            ),
            from: "no-reply@fantasticauth.local".to_string(),
            from_name: "FantasticAuth".to_string(),
            reply_to: None,
            headers: HashMap::new(),
        };

        if let Err(e) = service.send_email(request).await {
            warn!(email = %email, error = %e, "Failed to send welcome email");
        }
    }
}

fn parse_user_status(status: &str) -> anyhow::Result<UserStatus> {
    match status.to_lowercase().as_str() {
        "pending" => Ok(UserStatus::Pending),
        "active" => Ok(UserStatus::Active),
        "suspended" => Ok(UserStatus::Suspended),
        "deactivated" => Ok(UserStatus::Deactivated),
        "deleted" => Ok(UserStatus::Deleted),
        other => Err(anyhow::anyhow!("Invalid status: {}", other)),
    }
}

/// Generate a temporary password
/// 
/// SECURITY: Uses OsRng (operating system's CSPRNG) for cryptographically secure
/// password generation. Temporary passwords grant account access and must be
/// unpredictable to prevent unauthorized access to imported accounts.
fn generate_temporary_password() -> String {
    use rand::Rng;
    use rand_core::OsRng;

    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                            abcdefghijklmnopqrstuvwxyz\
                            0123456789\
                            !@#$%^&*";
    const LEN: usize = 16;

    // SECURITY: Use OsRng instead of thread_rng() for cryptographic security
    let mut rng = OsRng;
    let password: String = (0..LEN)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect();

    password
}

/// Get CSV template content
pub fn get_csv_template() -> String {
    CSV_TEMPLATE_HEADER.to_string()
}

/// Get JSON template content
pub fn get_json_template() -> String {
    JSON_TEMPLATE.to_string()
}

/// Count records in a file without fully parsing
pub async fn count_records(data: &[u8], format: FileFormat) -> anyhow::Result<usize> {
    match format {
        FileFormat::Csv => {
            let content = String::from_utf8_lossy(data);
            let cursor = Cursor::new(content.as_ref());
            let mut csv_reader = csv::ReaderBuilder::new()
                .has_headers(true)
                .from_reader(cursor);

            let mut count = 0;
            for result in csv_reader.records() {
                if result.is_ok() {
                    count += 1;
                }
            }
            Ok(count)
        }
        FileFormat::Json => {
            let parsed: Result<Vec<serde_json::Value>, _> = serde_json::from_slice(data);
            match parsed {
                Ok(array) => Ok(array.len()),
                Err(_) => {
                    // Try as single object
                    match serde_json::from_slice::<serde_json::Value>(data) {
                        Ok(_) => Ok(1),
                        Err(e) => Err(anyhow::anyhow!("Failed to parse JSON: {}", e)),
                    }
                }
            }
        }
    }
}
