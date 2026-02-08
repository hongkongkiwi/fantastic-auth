//! Bulk user import functionality
//!
//! Provides CSV and JSON parsing, validation, and batch insertion
//! with progress tracking and error collection.

use crate::bulk::{
    BulkImportJob, FileFormat, ImportError, ImportOptions, JobStatus, StorageConfig,
    UserImportRecord,
};
use crate::db::Database;
use std::io::Cursor;
use std::path::Path;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

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
}

impl ImportProcessor {
    /// Create a new import processor
    pub fn new(db: Database, storage_config: StorageConfig) -> Self {
        Self { db, storage_config }
    }

    /// Process an import job
    pub async fn process(&self, job: &mut BulkImportJob) -> anyhow::Result<()> {
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

        // Process records
        let mut errors = parse_result.errors;
        let batch_size = 100; // Process in batches

        for chunk in parse_result.records.chunks(batch_size) {
            for (row_number, record) in chunk {
                match self.import_user(job, record, *row_number).await {
                    Ok(_) => {
                        job.success_count += 1;
                    }
                    Err(e) => {
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

            // Small delay to avoid overwhelming the database
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        }

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
        use vault_core::crypto::VaultPasswordHasher;

        // Validate the record
        validate_record(record, row_number)
            .map_err(|e| anyhow::anyhow!("Validation failed: {}", e.error))?;

        // Check if user already exists
        let existing = self
            .db
            .users()
            .find_by_email(&job.tenant_id, &record.email)
            .await?;

        if existing.is_some() {
            if job.options.skip_existing {
                debug!(email = %record.email, "Skipping existing user");
                return Ok(());
            }

            if !job.options.update_existing {
                return Err(anyhow::anyhow!("User already exists: {}", record.email));
            }

            // TODO: Implement update logic
            return Ok(());
        }

        // Generate or use provided password
        let password_hash = if let Some(ref pwd) = record.password {
            if pwd == "AutoGenerate" {
                let generated = generate_temporary_password();
                VaultPasswordHasher::hash_password(&generated)?
            } else {
                VaultPasswordHasher::hash_password(pwd)?
            }
        } else if job.options.auto_generate_password {
            let generated = generate_temporary_password();
            VaultPasswordHasher::hash_password(&generated)?
        } else if let Some(ref default_pwd) = job.options.default_password {
            VaultPasswordHasher::hash_password(default_pwd)?
        } else {
            // No password - user will need to set via password reset
            None
        };

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

        // TODO: Send welcome email if configured

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
            .find_by_id(tenant_id, org_id)
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
}

/// Generate a temporary password
fn generate_temporary_password() -> String {
    use rand::Rng;

    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                            abcdefghijklmnopqrstuvwxyz\
                            0123456789\
                            !@#$%^&*";
    const LEN: usize = 16;

    let mut rng = rand::thread_rng();
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
