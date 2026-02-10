//! Bulk user export functionality
//!
//! Provides streaming export of users to CSV and JSON formats
//! with filtering and field selection.

use crate::bulk::{
    BulkExportJob, ExportOptions, FileFormat, JobStatus, StorageConfig, UserExportRecord,
};
use crate::db::Database;
use std::collections::HashSet;
use tokio::io::AsyncWriteExt;
use tracing::info;

/// Export processor for handling bulk exports
pub struct ExportProcessor {
    db: Database,
    storage_config: StorageConfig,
}

impl ExportProcessor {
    /// Create a new export processor
    pub fn new(db: Database, storage_config: StorageConfig) -> Self {
        Self { db, storage_config }
    }

    /// Process an export job
    pub async fn process(&self, job: &mut BulkExportJob) -> anyhow::Result<()> {
        info!(
            job_id = %job.id,
            tenant_id = %job.tenant_id,
            format = ?job.format,
            "Starting export job"
        );

        job.status = JobStatus::Processing;
        job.started_at = Some(chrono::Utc::now());

        // Create output file path
        let output_path = self.storage_config.result_path(job.id, job.format);

        // Ensure parent directory exists
        if let Some(parent) = output_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        // Create output file
        let mut file = tokio::fs::File::create(&output_path).await?;

        // Get user stream
        let tenant_id = job.tenant_id.clone();
        let options = job.options.clone();
        if options.include_password_hashes {
            anyhow::bail!("include_password_hashes is not supported for user exports");
        }
        let mut user_stream = UserStream::new(self.db.clone(), tenant_id, options.clone());

        match job.format {
            FileFormat::Csv => {
                self.export_csv(&mut file, &mut user_stream, job).await?;
            }
            FileFormat::Json => {
                self.export_json(&mut file, &mut user_stream, job).await?;
            }
        }

        // Flush and close file
        file.flush().await?;
        drop(file);

        // Mark job as completed
        job.status = JobStatus::Completed;
        job.completed_at = Some(chrono::Utc::now());
        job.result_file_path = Some(output_path);

        info!(
            job_id = %job.id,
            total_exported = job.total_records,
            "Export job completed"
        );

        Ok(())
    }

    /// Export users to CSV format
    async fn export_csv(
        &self,
        file: &mut tokio::fs::File,
        stream: &mut UserStream,
        job: &mut BulkExportJob,
    ) -> anyhow::Result<()> {
        // Write CSV header
        let header = "id,email,name,status,email_verified,role,organization_id,phone_number,mfa_enabled,last_login_at,created_at,updated_at\n";
        file.write_all(header.as_bytes()).await?;

        let mut count = 0;

        while let Some(mut record) = stream.next_record().await? {
            apply_field_filters(&mut record, &job.options);
            let csv_row = format_csv_row(&record);
            file.write_all(csv_row.as_bytes()).await?;
            count += 1;
            job.processed_records = count;

            // Check max records limit
            if job.options.max_records > 0 && count >= job.options.max_records {
                break;
            }
        }

        job.total_records = count;
        Ok(())
    }

    /// Export users to JSON format
    async fn export_json(
        &self,
        file: &mut tokio::fs::File,
        stream: &mut UserStream,
        job: &mut BulkExportJob,
    ) -> anyhow::Result<()> {
        // Start JSON array
        file.write_all(b"[\n").await?;

        let mut count = 0;
        let mut first = true;

        while let Some(mut record) = stream.next_record().await? {
            if !first {
                file.write_all(b",\n").await?;
            }
            first = false;

            apply_field_filters(&mut record, &job.options);
            let json = serde_json::to_string_pretty(&record)?;
            // Indent each line
            let indented: String =
                json.lines().map(|line| format!("  {}\n", line)).collect();
            file.write_all(indented.trim_end().as_bytes()).await?;

            count += 1;
            job.processed_records = count;

            // Check max records limit
            if job.options.max_records > 0 && count >= job.options.max_records {
                break;
            }
        }

        // End JSON array
        file.write_all(b"\n]\n").await?;

        job.total_records = count;
        Ok(())
    }
}

/// Format a UserExportRecord as CSV row
fn format_csv_row(record: &UserExportRecord) -> String {
    format!(
        "{},{},{},{},{},{},{},{},{},{},{},{}\n",
        escape_csv_field(&record.id),
        escape_csv_field(&record.email),
        escape_csv_field(&record.name.as_deref().unwrap_or("")),
        escape_csv_field(&record.status),
        record.email_verified,
        escape_csv_field(&record.role.as_deref().unwrap_or("")),
        escape_csv_field(&record.organization_id.as_deref().unwrap_or("")),
        escape_csv_field(&record.phone_number.as_deref().unwrap_or("")),
        record.mfa_enabled,
        record
            .last_login_at
            .map(|d| d.to_rfc3339())
            .unwrap_or_default(),
        record.created_at.to_rfc3339(),
        record.updated_at.to_rfc3339(),
    )
}

/// Escape a field for CSV output
fn escape_csv_field(field: &str) -> String {
    if field.contains(',') || field.contains('"') || field.contains('\n') || field.contains('\r') {
        let escaped = field.replace('"', "\"\"");
        format!("\"{}\"", escaped)
    } else {
        field.to_string()
    }
}

fn apply_field_filters(record: &mut UserExportRecord, options: &ExportOptions) {
    let include = if options.include_fields.is_empty() {
        None
    } else {
        Some(
            options
                .include_fields
                .iter()
                .map(|f| f.to_lowercase())
                .collect::<HashSet<_>>(),
        )
    };
    let exclude = options
        .exclude_fields
        .iter()
        .map(|f| f.to_lowercase())
        .collect::<HashSet<_>>();

    let selected = |name: &str| -> bool {
        let lowered = name.to_lowercase();
        let included = include.as_ref().is_none_or(|set| set.contains(&lowered));
        included && !exclude.contains(&lowered)
    };

    if !selected("id") {
        record.id.clear();
    }
    if !selected("email") {
        record.email.clear();
    }
    if !selected("name") {
        record.name = None;
    }
    if !selected("status") {
        record.status.clear();
    }
    if !selected("email_verified") {
        record.email_verified = false;
    }
    if !selected("role") {
        record.role = None;
    }
    if !selected("organization_id") {
        record.organization_id = None;
    }
    if !selected("phone_number") {
        record.phone_number = None;
    }
    if !selected("mfa_enabled") {
        record.mfa_enabled = false;
    }
    if !selected("last_login_at") {
        record.last_login_at = None;
    }
    if !selected("created_at") {
        record.created_at = epoch_utc();
    }
    if !selected("updated_at") {
        record.updated_at = epoch_utc();
    }
}

fn epoch_utc() -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::from_timestamp(0, 0).unwrap_or_else(chrono::Utc::now)
}

/// Stream of users from database
pub struct UserStream {
    db: Database,
    tenant_id: String,
    options: ExportOptions,
    offset: i64,
    batch_size: i64,
    buffer: Vec<UserExportRecord>,
    exhausted: bool,
}

impl UserStream {
    /// Create a new user stream
    pub fn new(db: Database, tenant_id: String, options: ExportOptions) -> Self {
        Self {
            db,
            tenant_id,
            options,
            offset: 0,
            batch_size: 100,
            buffer: Vec::new(),
            exhausted: false,
        }
    }

    /// Fetch next batch of users
    async fn fetch_batch(&mut self) -> anyhow::Result<()> {
        let limit = if self.options.max_records > 0 {
            self.batch_size
                .min(self.options.max_records as i64 - self.offset)
        } else {
            self.batch_size
        };

        if limit <= 0 {
            self.exhausted = true;
            return Ok(());
        }

        let mut query = String::from(
            r#"SELECT 
                u.id::text as id,
                u.email,
                u.profile->>'name' as name,
                u.status::text as status,
                u.email_verified,
                u.mfa_enabled,
                u.last_login_at,
                u.created_at,
                u.updated_at,
                u.profile->>'phone_number' as phone_number,
                om.role::text as role,
                om.organization_id::text as organization_id
            FROM users u
            LEFT JOIN organization_members om ON u.id = om.user_id 
                AND u.tenant_id = om.tenant_id
                AND om.status = 'active'"#,
        );

        let mut conditions = vec![
            "u.tenant_id = $1::uuid".to_string(),
            "u.deleted_at IS NULL".to_string(),
        ];
        let mut param_idx = 2;

        // Apply filters
        if let Some(ref status_filter) = self.options.status_filter {
            if !status_filter.is_empty() {
                let placeholders: Vec<String> = status_filter
                    .iter()
                    .enumerate()
                    .map(|(i, _)| format!("${}", param_idx + i))
                    .collect();
                conditions.push(format!("u.status::text IN ({})", placeholders.join(", ")));
                param_idx += status_filter.len();
            }
        }

        if let Some(ref org_id) = self.options.organization_id {
            conditions.push(format!("om.organization_id = ${}::uuid", param_idx));
            param_idx += 1;
        }

        if let Some(ref created_after) = self.options.created_after {
            conditions.push(format!("u.created_at >= ${}", param_idx));
            param_idx += 1;
        }

        if let Some(ref created_before) = self.options.created_before {
            conditions.push(format!("u.created_at <= ${}", param_idx));
            param_idx += 1;
        }

        query.push_str(" WHERE ");
        query.push_str(&conditions.join(" AND "));
        query.push_str(&format!(
            " ORDER BY u.created_at LIMIT ${} OFFSET ${}",
            param_idx,
            param_idx + 1
        ));

        // Build and execute query
        let mut sqlx_query = sqlx::query_as::<_, UserExportRow>(&query);
        sqlx_query = sqlx_query.bind(&self.tenant_id);

        if let Some(ref status_filter) = self.options.status_filter {
            for status in status_filter {
                sqlx_query = sqlx_query.bind(status);
            }
        }

        if let Some(ref org_id) = self.options.organization_id {
            sqlx_query = sqlx_query.bind(org_id);
        }

        if let Some(ref created_after) = self.options.created_after {
            sqlx_query = sqlx_query.bind(created_after);
        }

        if let Some(ref created_before) = self.options.created_before {
            sqlx_query = sqlx_query.bind(created_before);
        }

        sqlx_query = sqlx_query.bind(limit).bind(self.offset);

        let rows: Vec<UserExportRow> = sqlx_query.fetch_all(self.db.pool()).await?;

        if rows.is_empty() {
            self.exhausted = true;
        } else {
            self.buffer = rows.into_iter().map(|r| r.into()).collect();
            self.offset += limit;
        }

        Ok(())
    }
    
    async fn next_record(&mut self) -> anyhow::Result<Option<UserExportRecord>> {
        if self.exhausted {
            return Ok(None);
        }

        if self.buffer.is_empty() {
            self.fetch_batch().await?;
        }

        if self.buffer.is_empty() {
            self.exhausted = true;
            return Ok(None);
        }

        Ok(Some(self.buffer.remove(0)))
    }
}

/// Database row for user export
#[derive(Debug, Clone, sqlx::FromRow)]
struct UserExportRow {
    id: String,
    email: String,
    name: Option<String>,
    status: String,
    email_verified: bool,
    mfa_enabled: bool,
    last_login_at: Option<chrono::DateTime<chrono::Utc>>,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
    phone_number: Option<String>,
    role: Option<String>,
    organization_id: Option<String>,
}

impl From<UserExportRow> for UserExportRecord {
    fn from(row: UserExportRow) -> Self {
        Self {
            id: row.id,
            email: row.email,
            name: row.name,
            status: row.status,
            email_verified: row.email_verified,
            role: row.role,
            organization_id: row.organization_id,
            phone_number: row.phone_number,
            mfa_enabled: row.mfa_enabled,
            last_login_at: row.last_login_at,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

/// Export users synchronously (for smaller datasets)
pub async fn export_users_to_csv(
    db: &Database,
    tenant_id: &str,
    options: &ExportOptions,
) -> anyhow::Result<String> {
    let records: Vec<UserExportRecord> = Vec::new();

    // Build query
    let mut query = String::from(
        r#"SELECT 
            u.id::text as id,
            u.email,
            u.profile->>'name' as name,
            u.status::text as status,
            u.email_verified,
            u.mfa_enabled,
            u.last_login_at,
            u.created_at,
            u.updated_at,
            u.profile->>'phone_number' as phone_number,
            om.role::text as role,
            om.organization_id::text as organization_id
        FROM users u
        LEFT JOIN organization_members om ON u.id = om.user_id 
            AND u.tenant_id = om.tenant_id
            AND om.status = 'active'"#,
    );

    let mut conditions = vec![
        "u.tenant_id = $1::uuid".to_string(),
        "u.deleted_at IS NULL".to_string(),
    ];

    if options.organization_id.is_some() {
        conditions.push("om.organization_id = $2::uuid".to_string());
    }

    query.push_str(" WHERE ");
    query.push_str(&conditions.join(" AND "));
    query.push_str(" ORDER BY u.created_at");

    // SECURITY: Validate max_records to prevent injection and limit resource usage
    const MAX_EXPORT_RECORDS: usize = 100_000;
    let limit = if options.max_records > 0 {
        options.max_records.min(MAX_EXPORT_RECORDS)
    } else {
        MAX_EXPORT_RECORDS
    };
    
    // Use parameterized LIMIT (safe since we've validated it's a reasonable number)
    query.push_str(&format!(" LIMIT {}", limit));

    // Execute query
    let mut sqlx_query = sqlx::query_as::<_, UserExportRow>(&query);
    sqlx_query = sqlx_query.bind(tenant_id);

    if let Some(ref org_id) = options.organization_id {
        sqlx_query = sqlx_query.bind(org_id);
    }

    let rows: Vec<UserExportRow> = sqlx_query.fetch_all(db.pool()).await?;

    // Build CSV
    let mut csv = String::from("id,email,name,status,email_verified,role,organization_id,phone_number,mfa_enabled,last_login_at,created_at,updated_at\n");

    for row in rows {
        let mut record: UserExportRecord = row.into();
        apply_field_filters(&mut record, options);
        csv.push_str(&format_csv_row(&record));
    }

    Ok(csv)
}

/// Export users to JSON format synchronously
pub async fn export_users_to_json(
    db: &Database,
    tenant_id: &str,
    options: &ExportOptions,
) -> anyhow::Result<String> {
    // Build query
    let mut query = String::from(
        r#"SELECT 
            u.id::text as id,
            u.email,
            u.profile->>'name' as name,
            u.status::text as status,
            u.email_verified,
            u.mfa_enabled,
            u.last_login_at,
            u.created_at,
            u.updated_at,
            u.profile->>'phone_number' as phone_number,
            om.role::text as role,
            om.organization_id::text as organization_id
        FROM users u
        LEFT JOIN organization_members om ON u.id = om.user_id 
            AND u.tenant_id = om.tenant_id
            AND om.status = 'active'"#,
    );

    let mut conditions = vec![
        "u.tenant_id = $1::uuid".to_string(),
        "u.deleted_at IS NULL".to_string(),
    ];

    if options.organization_id.is_some() {
        conditions.push("om.organization_id = $2::uuid".to_string());
    }

    query.push_str(" WHERE ");
    query.push_str(&conditions.join(" AND "));
    query.push_str(" ORDER BY u.created_at");

    // SECURITY: Validate max_records to prevent injection and limit resource usage
    const MAX_EXPORT_RECORDS: usize = 100_000;
    let limit = if options.max_records > 0 {
        options.max_records.min(MAX_EXPORT_RECORDS)
    } else {
        MAX_EXPORT_RECORDS
    };
    
    // Use parameterized LIMIT (safe since we've validated it's a reasonable number)
    query.push_str(&format!(" LIMIT {}", limit));

    // Execute query
    let mut sqlx_query = sqlx::query_as::<_, UserExportRow>(&query);
    sqlx_query = sqlx_query.bind(tenant_id);

    if let Some(ref org_id) = options.organization_id {
        sqlx_query = sqlx_query.bind(org_id);
    }

    let rows: Vec<UserExportRow> = sqlx_query.fetch_all(db.pool()).await?;

    let records: Vec<UserExportRecord> = rows
        .into_iter()
        .map(|r| {
            let mut record: UserExportRecord = r.into();
            apply_field_filters(&mut record, options);
            record
        })
        .collect();

    Ok(serde_json::to_string_pretty(&records)?)
}
