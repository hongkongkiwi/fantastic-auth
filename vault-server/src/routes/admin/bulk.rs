//! Admin Bulk Operations Routes
//!
//! Provides import/export endpoints for bulk user management.
//!
//! Endpoints:
//! - POST /api/v1/admin/bulk/import - Upload CSV/JSON for import
//! - GET /api/v1/admin/bulk/import/:job_id - Check import status
//! - GET /api/v1/admin/bulk/import/:job_id/download - Download error report
//! - GET /api/v1/admin/bulk/template/:format - Download import template
//! - POST /api/v1/admin/bulk/export - Start export
//! - GET /api/v1/admin/bulk/export/:job_id - Check export status
//! - GET /api/v1/admin/bulk/export/:job_id/download - Download export file
//! - GET /api/v1/admin/bulk/jobs - List bulk jobs
//! - DELETE /api/v1/admin/bulk/jobs/:job_id - Cancel/delete job

use axum::{
    extract::{DefaultBodyLimit, Multipart, Path, Query, State},
    http::{header, StatusCode},
    response::IntoResponse,
    routing::{delete, get, post},
    Extension, Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tokio::io::AsyncWriteExt;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::audit::{AuditAction, AuditLogger, ResourceType};
use crate::bulk::{
    BulkExportJob, BulkImportJob, BulkJobRow, ExportOptions, FileFormat, ImportOptions,
    JobProgress, JobStatus, JobType, StorageConfig,
};
use crate::routes::ApiError;
use crate::state::{AppState, CurrentUser};

/// Maximum file upload size (10MB)
const MAX_UPLOAD_SIZE: usize = 10 * 1024 * 1024;

/// Bulk routes
pub fn routes() -> Router<AppState> {
    Router::new()
        // Import endpoints
        .route("/bulk/import", post(start_import))
        .route("/bulk/import/:job_id", get(get_import_status))
        .route("/bulk/import/:job_id/download", get(download_error_report))
        .route("/bulk/template/:format", get(download_template))
        // Export endpoints
        .route("/bulk/export", post(start_export))
        .route("/bulk/export/:job_id", get(get_export_status))
        .route("/bulk/export/:job_id/download", get(download_export_file))
        // Job management
        .route("/bulk/jobs", get(list_jobs))
        .route("/bulk/jobs/:job_id", delete(delete_job))
        // Increase body limit for file uploads
        .layer(DefaultBodyLimit::max(MAX_UPLOAD_SIZE))
}

// ============ Request/Response Types ============

/// Import request body (for JSON API)
#[derive(Debug, Deserialize)]
struct ImportRequest {
    /// Base64 encoded file content (alternative to multipart)
    #[serde(skip_serializing_if = "Option::is_none")]
    file_content: Option<String>,
    /// File format
    format: FileFormat,
    /// Import options
    #[serde(default)]
    options: ImportOptions,
}

/// Start import response
#[derive(Debug, Serialize)]
struct ImportResponse {
    #[serde(rename = "jobId")]
    job_id: String,
    status: String,
    message: String,
}

/// Import status response
#[derive(Debug, Serialize)]
struct ImportStatusResponse {
    #[serde(rename = "jobId")]
    job_id: String,
    status: String,
    format: String,
    #[serde(rename = "totalRecords")]
    total_records: usize,
    #[serde(rename = "processedRecords")]
    processed_records: usize,
    #[serde(rename = "successCount")]
    success_count: usize,
    #[serde(rename = "errorCount")]
    error_count: usize,
    progress: u8,
    #[serde(rename = "hasErrors")]
    has_errors: bool,
    #[serde(rename = "errorReportUrl")]
    error_report_url: Option<String>,
    #[serde(rename = "createdAt")]
    created_at: DateTime<Utc>,
    #[serde(rename = "startedAt")]
    started_at: Option<DateTime<Utc>>,
    #[serde(rename = "completedAt")]
    completed_at: Option<DateTime<Utc>>,
}

/// Export request body
#[derive(Debug, Deserialize)]
struct ExportRequest {
    /// File format
    format: FileFormat,
    /// Export options
    #[serde(default)]
    options: ExportOptions,
}

/// Start export response
#[derive(Debug, Serialize)]
struct ExportResponse {
    #[serde(rename = "jobId")]
    job_id: String,
    status: String,
    message: String,
}

/// Export status response
#[derive(Debug, Serialize)]
struct ExportStatusResponse {
    #[serde(rename = "jobId")]
    job_id: String,
    status: String,
    format: String,
    #[serde(rename = "totalRecords")]
    total_records: usize,
    #[serde(rename = "processedRecords")]
    processed_records: usize,
    progress: u8,
    #[serde(rename = "downloadUrl")]
    download_url: Option<String>,
    #[serde(rename = "createdAt")]
    created_at: DateTime<Utc>,
    #[serde(rename = "startedAt")]
    started_at: Option<DateTime<Utc>>,
    #[serde(rename = "completedAt")]
    completed_at: Option<DateTime<Utc>>,
}

/// List jobs query parameters
#[derive(Debug, Deserialize)]
struct ListJobsQuery {
    #[serde(rename = "type")]
    job_type: Option<String>,
    status: Option<String>,
    #[serde(default)]
    limit: usize,
}

impl Default for ListJobsQuery {
    fn default() -> Self {
        Self {
            job_type: None,
            status: None,
            limit: 50,
        }
    }
}

/// Job list item
#[derive(Debug, Serialize)]
struct JobListItem {
    #[serde(rename = "jobId")]
    job_id: String,
    #[serde(rename = "jobType")]
    job_type: String,
    status: String,
    format: String,
    #[serde(rename = "totalRecords")]
    total_records: usize,
    #[serde(rename = "successCount")]
    success_count: usize,
    #[serde(rename = "errorCount")]
    error_count: usize,
    #[serde(rename = "createdAt")]
    created_at: DateTime<Utc>,
    #[serde(rename = "completedAt")]
    completed_at: Option<DateTime<Utc>>,
}

/// Delete job response
#[derive(Debug, Serialize)]
struct DeleteJobResponse {
    message: String,
}

// ============ Import Handlers ============

/// Start a bulk import job with multipart file upload
async fn start_import(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    mut multipart: Multipart,
) -> Result<Json<ImportResponse>, ApiError> {
    // Set tenant context
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    // Parse multipart form
    let mut file_data: Option<(String, Vec<u8>)> = None; // (filename, data)
    let mut format: Option<FileFormat> = None;
    let mut options = ImportOptions::default();

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| ApiError::BadRequest(format!("Failed to parse multipart: {}", e)))?
    {
        let name = field.name().map(|s| s.to_string());

        match name.as_deref() {
            Some("file") => {
                let filename = field
                    .file_name()
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "import.csv".to_string());

                let data = field
                    .bytes()
                    .await
                    .map_err(|e| ApiError::BadRequest(format!("Failed to read file: {}", e)))?;

                if data.len() > MAX_UPLOAD_SIZE {
                    return Err(ApiError::BadRequest(format!(
                        "File too large. Maximum size is {}MB",
                        MAX_UPLOAD_SIZE / 1024 / 1024
                    )));
                }

                // Auto-detect format from filename
                if format.is_none() {
                    if filename.ends_with(".json") {
                        format = Some(FileFormat::Json);
                    } else {
                        format = Some(FileFormat::Csv);
                    }
                }

                file_data = Some((filename, data.to_vec()));
            }
            Some("format") => {
                let value = field
                    .text()
                    .await
                    .map_err(|e| ApiError::BadRequest(format!("Invalid format: {}", e)))?;
                format = Some(value.parse().map_err(|_| {
                    ApiError::BadRequest("Invalid format. Use 'csv' or 'json'".to_string())
                })?);
            }
            Some("continueOnError") => {
                let value = field
                    .text()
                    .await
                    .map_err(|_| ApiError::BadRequest("Invalid continueOnError".to_string()))?;
                options.continue_on_error = value.parse().unwrap_or(true);
            }
            Some("previewMode") => {
                let value = field
                    .text()
                    .await
                    .map_err(|_| ApiError::BadRequest("Invalid previewMode".to_string()))?;
                options.preview_mode = value.parse().unwrap_or(false);
            }
            Some("autoGeneratePassword") => {
                let value = field.text().await.map_err(|_| {
                    ApiError::BadRequest("Invalid autoGeneratePassword".to_string())
                })?;
                options.auto_generate_password = value.parse().unwrap_or(false);
            }
            Some("skipExisting") => {
                let value = field
                    .text()
                    .await
                    .map_err(|_| ApiError::BadRequest("Invalid skipExisting".to_string()))?;
                options.skip_existing = value.parse().unwrap_or(false);
            }
            Some("organizationId") => {
                options.organization_id = Some(
                    field
                        .text()
                        .await
                        .map_err(|_| ApiError::BadRequest("Invalid organizationId".to_string()))?,
                );
            }
            _ => {}
        }
    }

    let (filename, data) = file_data
        .ok_or_else(|| ApiError::BadRequest("No file uploaded. Use 'file' field.".to_string()))?;

    let format = format
        .ok_or_else(|| ApiError::BadRequest("Could not determine file format".to_string()))?;

    // Create storage config and ensure directories exist
    let storage_config = StorageConfig::from_env();
    storage_config
        .ensure_dirs()
        .await
        .map_err(|_| ApiError::Internal)?;

    // Create job
    let job_id = Uuid::new_v4();
    let file_path = storage_config.upload_path(job_id);

    // Save uploaded file
    tokio::fs::write(&file_path, &data)
        .await
        .map_err(|_| ApiError::Internal)?;

    // Parse and validate file to count records
    let parse_result = crate::bulk::import::parse_file(&data, format)
        .map_err(|e| ApiError::BadRequest(format!("Failed to parse file: {}", e)))?;

    // Create job in database
    let job = BulkImportJob {
        id: job_id,
        tenant_id: current_user.tenant_id.clone(),
        status: JobStatus::Pending,
        format,
        total_records: parse_result.total,
        processed_records: 0,
        success_count: 0,
        error_count: parse_result.errors.len(),
        file_path: Some(file_path.clone()),
        error_report_path: None,
        created_by: current_user.user_id.clone(),
        created_at: Utc::now(),
        started_at: None,
        completed_at: None,
        options: options.clone(),
        error_message: None,
    };

    // Save job to database
    save_import_job(&state, &job)
        .await
        .map_err(|_| ApiError::Internal)?;

    // If preview mode, process immediately
    if options.preview_mode {
        info!(job_id = %job_id, "Processing import in preview mode");

        let mut job_clone = job.clone();
        let processor =
            crate::bulk::import::ImportProcessor::new(state.db.clone(), storage_config.clone());

        // Process in background
        tokio::spawn(async move {
            if let Err(e) = processor.process(&mut job_clone).await {
                error!(job_id = %job_id, error = %e, "Import processing failed");
            }
            // TODO: Update job status in database
        });
    } else {
        // Queue for background processing
        info!(job_id = %job_id, "Queuing import job for background processing");

        // Spawn background task
        let db = state.db.clone();
        let mut job_clone = job.clone();

        tokio::spawn(async move {
            let processor = crate::bulk::import::ImportProcessor::new(db, storage_config);

            if let Err(e) = processor.process(&mut job_clone).await {
                error!(job_id = %job_id, error = %e, "Import processing failed");
            }
            // TODO: Update job status in database
        });
    }

    // Audit log
    let audit = AuditLogger::new(state.db.clone());
    audit.log(
        &current_user.tenant_id,
        AuditAction::BulkImportStarted,
        ResourceType::BulkJob,
        &job_id.to_string(),
        Some(current_user.user_id.clone()),
        None,
        None,
        true,
        Some(format!(
            "Started bulk import: {} records, format: {:?}",
            parse_result.total, format
        )),
        Some(serde_json::json!({
            "filename": filename,
            "format": format,
            "record_count": parse_result.total,
            "preview_mode": options.preview_mode,
        })),
    );

    Ok(Json(ImportResponse {
        job_id: job_id.to_string(),
        status: "pending".to_string(),
        message: if options.preview_mode {
            "Import validation in progress".to_string()
        } else {
            "Import job queued".to_string()
        },
    }))
}

/// Get import job status
async fn get_import_status(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(job_id): Path<String>,
) -> Result<Json<ImportStatusResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let job_uuid =
        Uuid::parse_str(&job_id).map_err(|_| ApiError::BadRequest("Invalid job ID".to_string()))?;

    let row = get_job_row(&state, &job_uuid)
        .await
        .map_err(|_| ApiError::Internal)?
        .ok_or(ApiError::NotFound)?;

    // Verify tenant ownership
    if row.tenant_id.to_string() != current_user.tenant_id {
        return Err(ApiError::Forbidden);
    }

    // Verify job type
    if row.job_type != "import" {
        return Err(ApiError::BadRequest("Not an import job".to_string()));
    }

    let total = row.total_records as usize;
    let processed = row.processed_records as usize;
    let progress = if total > 0 {
        ((processed as f64 / total as f64) * 100.0) as u8
    } else {
        0
    };

    let error_report_url = if row.error_count > 0 {
        Some(format!("/api/v1/admin/bulk/import/{}/download", job_id))
    } else {
        None
    };

    Ok(Json(ImportStatusResponse {
        job_id,
        status: row.status,
        format: row.format,
        total_records: total,
        processed_records: processed,
        success_count: row.success_count as usize,
        error_count: row.error_count as usize,
        progress,
        has_errors: row.error_count > 0,
        error_report_url,
        created_at: row.created_at,
        started_at: row.started_at,
        completed_at: row.completed_at,
    }))
}

/// Download import error report
async fn download_error_report(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(job_id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let job_uuid =
        Uuid::parse_str(&job_id).map_err(|_| ApiError::BadRequest("Invalid job ID".to_string()))?;

    let row = get_job_row(&state, &job_uuid)
        .await
        .map_err(|_| ApiError::Internal)?
        .ok_or(ApiError::NotFound)?;

    // Verify tenant ownership
    if row.tenant_id.to_string() != current_user.tenant_id {
        return Err(ApiError::Forbidden);
    }

    if row.job_type != "import" {
        return Err(ApiError::BadRequest("Not an import job".to_string()));
    }

    // Get error report path
    let error_path = row.error_report_path.ok_or_else(|| ApiError::NotFound)?;

    // Read error report
    let content = tokio::fs::read_to_string(&error_path)
        .await
        .map_err(|_| ApiError::NotFound)?;

    let filename = format!("import_errors_{}.json", job_id);

    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/json"),
            (
                header::CONTENT_DISPOSITION,
                &format!("attachment; filename=\"{}\"", filename),
            ),
        ],
        content,
    ))
}

/// Download import template
async fn download_template(Path(format): Path<String>) -> Result<impl IntoResponse, ApiError> {
    let format: FileFormat = format
        .parse()
        .map_err(|_| ApiError::BadRequest("Invalid format. Use 'csv' or 'json'".to_string()))?;

    let (content, filename, content_type) = match format {
        FileFormat::Csv => {
            let content = crate::bulk::import::get_csv_template();
            (content, "import_template.csv", "text/csv")
        }
        FileFormat::Json => {
            let content = crate::bulk::import::get_json_template();
            (content, "import_template.json", "application/json")
        }
    };

    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, content_type),
            (
                header::CONTENT_DISPOSITION,
                &format!("attachment; filename=\"{}\"", filename),
            ),
        ],
        content,
    ))
}

// ============ Export Handlers ============

/// Start a bulk export job
async fn start_export(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<ExportRequest>,
) -> Result<Json<ExportResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    // Create storage config
    let storage_config = StorageConfig::from_env();
    storage_config
        .ensure_dirs()
        .await
        .map_err(|_| ApiError::Internal)?;

    // Create job
    let job_id = Uuid::new_v4();

    let job = BulkExportJob {
        id: job_id,
        tenant_id: current_user.tenant_id.clone(),
        status: JobStatus::Pending,
        format: req.format,
        total_records: 0,
        processed_records: 0,
        result_file_path: None,
        created_by: current_user.user_id.clone(),
        created_at: Utc::now(),
        started_at: None,
        completed_at: None,
        options: req.options.clone(),
        error_message: None,
    };

    // Save job to database
    save_export_job(&state, &job)
        .await
        .map_err(|_| ApiError::Internal)?;

    // Spawn background processing
    let db = state.db.clone();
    let mut job_clone = job.clone();

    tokio::spawn(async move {
        let processor = crate::bulk::export::ExportProcessor::new(db, storage_config);

        if let Err(e) = processor.process(&mut job_clone).await {
            error!(job_id = %job_id, error = %e, "Export processing failed");
        }
        // TODO: Update job status in database
    });

    // Audit log
    let audit = AuditLogger::new(state.db.clone());
    audit.log(
        &current_user.tenant_id,
        AuditAction::BulkExportStarted,
        ResourceType::BulkJob,
        &job_id.to_string(),
        Some(current_user.user_id.clone()),
        None,
        None,
        true,
        Some(format!("Started bulk export, format: {:?}", req.format)),
        Some(serde_json::json!({
            "format": req.format,
            "options": req.options,
        })),
    );

    Ok(Json(ExportResponse {
        job_id: job_id.to_string(),
        status: "pending".to_string(),
        message: "Export job queued".to_string(),
    }))
}

/// Get export job status
async fn get_export_status(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(job_id): Path<String>,
) -> Result<Json<ExportStatusResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let job_uuid =
        Uuid::parse_str(&job_id).map_err(|_| ApiError::BadRequest("Invalid job ID".to_string()))?;

    let row = get_job_row(&state, &job_uuid)
        .await
        .map_err(|_| ApiError::Internal)?
        .ok_or(ApiError::NotFound)?;

    // Verify tenant ownership
    if row.tenant_id.to_string() != current_user.tenant_id {
        return Err(ApiError::Forbidden);
    }

    if row.job_type != "export" {
        return Err(ApiError::BadRequest("Not an export job".to_string()));
    }

    let total = row.total_records as usize;
    let processed = row.processed_records as usize;
    let progress = if total > 0 {
        ((processed as f64 / total as f64) * 100.0) as u8
    } else {
        0
    };

    let download_url = if row.status == "completed" {
        Some(format!("/api/v1/admin/bulk/export/{}/download", job_id))
    } else {
        None
    };

    Ok(Json(ExportStatusResponse {
        job_id,
        status: row.status,
        format: row.format,
        total_records: total,
        processed_records: processed,
        progress,
        download_url,
        created_at: row.created_at,
        started_at: row.started_at,
        completed_at: row.completed_at,
    }))
}

/// Download export file
async fn download_export_file(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(job_id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let job_uuid =
        Uuid::parse_str(&job_id).map_err(|_| ApiError::BadRequest("Invalid job ID".to_string()))?;

    let row = get_job_row(&state, &job_uuid)
        .await
        .map_err(|_| ApiError::Internal)?
        .ok_or(ApiError::NotFound)?;

    // Verify tenant ownership
    if row.tenant_id.to_string() != current_user.tenant_id {
        return Err(ApiError::Forbidden);
    }

    if row.job_type != "export" {
        return Err(ApiError::BadRequest("Not an export job".to_string()));
    }

    if row.status != "completed" {
        return Err(ApiError::BadRequest("Export not yet complete".to_string()));
    }

    // Get result file path
    let result_path = row.result_file_path.ok_or_else(|| ApiError::NotFound)?;

    // Read file
    let content = tokio::fs::read(&result_path)
        .await
        .map_err(|_| ApiError::NotFound)?;

    let extension = if row.format == "csv" { "csv" } else { "json" };
    let filename = format!("users_export_{}.{}.{}", job_id, row.format, extension);
    let content_type = if row.format == "csv" {
        "text/csv"
    } else {
        "application/json"
    };

    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, content_type),
            (
                header::CONTENT_DISPOSITION,
                &format!("attachment; filename=\"{}\"", filename),
            ),
        ],
        content,
    ))
}

// ============ Job Management Handlers ============

/// List bulk jobs
async fn list_jobs(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Query(query): Query<ListJobsQuery>,
) -> Result<Json<Vec<JobListItem>>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let limit = query.limit.max(1).min(100);

    let rows = sqlx::query_as::<_, BulkJobRow>(
        r#"SELECT 
            id, tenant_id, job_type, status, format,
            total_records, processed_records, success_count, error_count,
            file_path, error_report_path, result_file_path,
            options, error_message, created_by, created_at, started_at, completed_at
        FROM bulk_jobs
        WHERE tenant_id = $1::uuid
        AND ($2::text IS NULL OR job_type = $2)
        AND ($3::text IS NULL OR status = $3)
        ORDER BY created_at DESC
        LIMIT $4"#,
    )
    .bind(&current_user.tenant_id)
    .bind(&query.job_type)
    .bind(&query.status)
    .bind(limit as i64)
    .fetch_all(state.db.pool())
    .await
    .map_err(|_| ApiError::Internal)?;

    let items: Vec<JobListItem> = rows
        .into_iter()
        .map(|row| JobListItem {
            job_id: row.id.to_string(),
            job_type: row.job_type,
            status: row.status,
            format: row.format,
            total_records: row.total_records as usize,
            success_count: row.success_count as usize,
            error_count: row.error_count as usize,
            created_at: row.created_at,
            completed_at: row.completed_at,
        })
        .collect();

    Ok(Json(items))
}

/// Delete/cancel a bulk job
async fn delete_job(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(job_id): Path<String>,
) -> Result<Json<DeleteJobResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let job_uuid =
        Uuid::parse_str(&job_id).map_err(|_| ApiError::BadRequest("Invalid job ID".to_string()))?;

    // Get job to verify ownership
    let row = get_job_row(&state, &job_uuid)
        .await
        .map_err(|_| ApiError::Internal)?
        .ok_or(ApiError::NotFound)?;

    if row.tenant_id.to_string() != current_user.tenant_id {
        return Err(ApiError::Forbidden);
    }

    // Can only delete completed or failed jobs
    if row.status == "processing" {
        return Err(ApiError::BadRequest(
            "Cannot delete a job that is currently processing".to_string(),
        ));
    }

    // Delete from database
    sqlx::query("DELETE FROM bulk_jobs WHERE id = $1::uuid AND tenant_id = $2::uuid")
        .bind(&job_uuid)
        .bind(&current_user.tenant_id)
        .execute(state.db.pool())
        .await
        .map_err(|_| ApiError::Internal)?;

    // Clean up files
    let storage = StorageConfig::from_env();

    if let Some(ref file_path) = row.file_path {
        let _ = tokio::fs::remove_file(file_path).await;
    }
    if let Some(ref error_path) = row.error_report_path {
        let _ = tokio::fs::remove_file(error_path).await;
    }
    if let Some(ref result_path) = row.result_file_path {
        let _ = tokio::fs::remove_file(result_path).await;
    }

    // Audit log
    let audit = AuditLogger::new(state.db.clone());
    audit.log(
        &current_user.tenant_id,
        AuditAction::BulkJobDeleted,
        ResourceType::BulkJob,
        &job_id,
        Some(current_user.user_id.clone()),
        None,
        None,
        true,
        Some(format!("Deleted bulk job: {}", row.job_type)),
        None,
    );

    Ok(Json(DeleteJobResponse {
        message: "Job deleted successfully".to_string(),
    }))
}

// ============ Database Helpers ============

/// Get a job row from database
async fn get_job_row(state: &AppState, job_id: &Uuid) -> anyhow::Result<Option<BulkJobRow>> {
    let row = sqlx::query_as::<_, BulkJobRow>(
        r#"SELECT 
            id, tenant_id, job_type, status, format,
            total_records, processed_records, success_count, error_count,
            file_path, error_report_path, result_file_path,
            options, error_message, created_by, created_at, started_at, completed_at
        FROM bulk_jobs
        WHERE id = $1"#,
    )
    .bind(job_id)
    .fetch_optional(state.db.pool())
    .await?;

    Ok(row)
}

/// Save import job to database
async fn save_import_job(state: &AppState, job: &BulkImportJob) -> anyhow::Result<()> {
    sqlx::query(
        r#"INSERT INTO bulk_jobs 
           (id, tenant_id, job_type, status, format,
            total_records, processed_records, success_count, error_count,
            file_path, options, created_by, created_at)
           VALUES ($1, $2::uuid, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::uuid, $13)"#,
    )
    .bind(job.id)
    .bind(&job.tenant_id)
    .bind("import")
    .bind(format!("{:?}", job.status).to_lowercase())
    .bind(format!("{:?}", job.format).to_lowercase())
    .bind(job.total_records as i32)
    .bind(job.processed_records as i32)
    .bind(job.success_count as i32)
    .bind(job.error_count as i32)
    .bind(
        job.file_path
            .as_ref()
            .map(|p| p.to_string_lossy().to_string()),
    )
    .bind(serde_json::to_value(&job.options)?)
    .bind(Uuid::parse_str(&job.created_by)?)
    .bind(job.created_at)
    .execute(state.db.pool())
    .await?;

    Ok(())
}

/// Save export job to database
async fn save_export_job(state: &AppState, job: &BulkExportJob) -> anyhow::Result<()> {
    sqlx::query(
        r#"INSERT INTO bulk_jobs 
           (id, tenant_id, job_type, status, format,
            total_records, processed_records, success_count, error_count,
            options, created_by, created_at)
           VALUES ($1, $2::uuid, $3, $4, $5, $6, $7, $8, $9, $10, $11::uuid, $12)"#,
    )
    .bind(job.id)
    .bind(&job.tenant_id)
    .bind("export")
    .bind(format!("{:?}", job.status).to_lowercase())
    .bind(format!("{:?}", job.format).to_lowercase())
    .bind(0i32) // total_records will be updated
    .bind(0i32) // processed_records
    .bind(0i32) // success_count
    .bind(0i32) // error_count
    .bind(serde_json::to_value(&job.options)?)
    .bind(Uuid::parse_str(&job.created_by)?)
    .bind(job.created_at)
    .execute(state.db.pool())
    .await?;

    Ok(())
}
