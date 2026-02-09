//! Admin API routes for user migrations
//!
//! Endpoints:
//! - POST /api/v1/admin/migrations/auth0 - Migrate from Auth0
//! - POST /api/v1/admin/migrations/firebase - Migrate from Firebase
//! - POST /api/v1/admin/migrations/cognito - Migrate from AWS Cognito
//! - POST /api/v1/admin/migrations/csv - Import from CSV
//! - GET /api/v1/admin/migrations - List migration jobs
//! - GET /api/v1/admin/migrations/:id - Get migration job details
//! - GET /api/v1/admin/migrations/:id/progress - Get real-time progress
//! - GET /api/v1/admin/migrations/:id/errors - Get migration errors
//! - POST /api/v1/admin/migrations/:id/cancel - Cancel a migration
//! - POST /api/v1/admin/migrations/:id/resume - Resume a failed migration
//! - POST /api/v1/admin/migrations/validate/csv - Validate CSV before import

use axum::{
    extract::{DefaultBodyLimit, Multipart, Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};

use crate::audit::{AuditAction, AuditLogger, RequestContext, ResourceType};
use crate::migration::{
    Auth0Config, CognitoConfig, CsvConfig, FirebaseConfig, MigrationOptions,
    MigrationService,
};
use crate::routes::ApiError;
use crate::state::{AppState, CurrentUser};

/// Maximum CSV file size: 100MB
const MAX_CSV_SIZE: usize = 100 * 1024 * 1024;

/// Create migration routes
pub fn routes() -> Router<AppState> {
    Router::new()
        // Start migrations
        .route("/migrations/auth0", post(migrate_from_auth0))
        .route("/migrations/firebase", post(migrate_from_firebase))
        .route("/migrations/cognito", post(migrate_from_cognito))
        .route("/migrations/csv", post(migrate_from_csv))
        // Validation
        .route("/migrations/validate/csv", post(validate_csv))
        // List and get jobs
        .route("/migrations", get(list_migrations))
        .route("/migrations/:id", get(get_migration))
        .route("/migrations/:id/progress", get(get_migration_progress))
        .route("/migrations/:id/errors", get(get_migration_errors))
        // Control operations
        .route("/migrations/:id/cancel", post(cancel_migration))
        .route("/migrations/:id/resume", post(resume_migration))
        .route("/migrations/:id/pause", post(pause_migration))
        // CSV preview
        .route("/migrations/preview/csv", post(preview_csv))
        // Increase body limit for CSV uploads
        .layer(DefaultBodyLimit::max(MAX_CSV_SIZE))
}

// ============ Request/Response Types ============

/// Auth0 migration request
#[derive(Debug, Deserialize)]
struct Auth0MigrationRequest {
    #[serde(flatten)]
    config: Auth0Config,
    #[serde(default)]
    options: Option<MigrationOptions>,
    #[serde(default)]
    dry_run: bool,
}

/// Firebase migration request
#[derive(Debug, Deserialize)]
struct FirebaseMigrationRequest {
    #[serde(flatten)]
    config: FirebaseConfig,
    #[serde(default)]
    options: Option<MigrationOptions>,
    #[serde(default)]
    dry_run: bool,
}

/// Cognito migration request
#[derive(Debug, Deserialize)]
struct CognitoMigrationRequest {
    #[serde(flatten)]
    config: CognitoConfig,
    #[serde(default)]
    options: Option<MigrationOptions>,
    #[serde(default)]
    dry_run: bool,
}

/// CSV import request
#[derive(Debug, Deserialize)]
struct CsvImportRequest {
    config: CsvConfig,
    #[serde(default)]
    options: Option<MigrationOptions>,
    #[serde(default)]
    dry_run: bool,
}

/// Migration response
#[derive(Debug, Serialize)]
struct MigrationResponse {
    id: String,
    source: String,
    status: String,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    dry_run: Option<bool>,
}

/// Migration detail response
#[derive(Debug, Serialize)]
struct MigrationDetailResponse {
    id: String,
    source: String,
    status: String,
    total_users: i32,
    processed: i32,
    succeeded: i32,
    failed: i32,
    dry_run: bool,
    percent_complete: f64,
    started_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    completed_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    duration_secs: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    created_by: Option<String>,
}

/// Migration list response
#[derive(Debug, Serialize)]
struct MigrationListResponse {
    migrations: Vec<MigrationDetailResponse>,
    total: i64,
}

/// Progress response
#[derive(Debug, Serialize)]
struct ProgressResponse {
    id: String,
    source: String,
    status: String,
    total_users: usize,
    processed: usize,
    succeeded: usize,
    failed: usize,
    percent_complete: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    estimated_remaining_secs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    current_operation: Option<String>,
}

/// Error response
#[derive(Debug, Serialize)]
struct ErrorResponse {
    errors: Vec<ErrorDetail>,
    total: i64,
}

#[derive(Debug, Serialize)]
struct ErrorDetail {
    #[serde(skip_serializing_if = "Option::is_none")]
    external_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    created_at: Option<String>,
}

/// CSV preview response
#[derive(Debug, Serialize)]
struct CsvPreviewResponse {
    total_rows: usize,
    sample: Vec<CsvUserPreview>,
    detected_config: CsvConfig,
    validation_result: ValidationResultResponse,
}

#[derive(Debug, Serialize)]
struct CsvUserPreview {
    email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    phone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<String>,
}

#[derive(Debug, Serialize)]
struct ValidationResultResponse {
    valid: bool,
    errors: Vec<String>,
    warnings: Vec<String>,
}

/// List query parameters
#[derive(Debug, Deserialize)]
struct ListMigrationsQuery {
    #[serde(default = "default_limit")]
    limit: usize,
    #[serde(default)]
    offset: usize,
}

fn default_limit() -> usize {
    20
}

// ============ Handlers ============

/// Migrate users from Auth0
async fn migrate_from_auth0(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(request): Json<Auth0MigrationRequest>,
) -> Result<Json<MigrationResponse>, ApiError> {
    let service = MigrationService::new(state.db.clone(), state.redis.clone());

    let mut options = request.options.unwrap_or_default();
    options.dry_run = request.dry_run;

    let tenant_id = current_user.tenant_id.clone();
    let created_by = current_user.user_id.clone();
    let config = request.config;

    let result = service
        .migrate_from_auth0(
            &tenant_id,
            config.clone(),
            Some(options.clone()),
            Some(&created_by),
        )
        .await
        .map_err(|e| {
            tracing::error!("Failed to start Auth0 migration: {}", e);
            ApiError::bad_request(format!("Failed to start migration: {}", e))
        })?;
    let job_id = result.job_id.clone();

    // Audit log
    let audit = AuditLogger::new(state.db.clone());
    audit.log(
        tenant_id.clone(),
        AuditAction::Custom("migration.auth0.started"),
        ResourceType::BulkJob,
        &job_id,
        Some(created_by),
        None,
        None,
        true,
        None,
        Some(serde_json::json!({
            "domain": config.domain,
            "dry_run": options.dry_run,
        })),
    );

    Ok(Json(MigrationResponse {
        id: job_id,
        source: "auth0".to_string(),
        status: "completed".to_string(),
        message: "Migration completed".to_string(),
        dry_run: Some(result.dry_run),
    }))
}

/// Migrate users from Firebase
async fn migrate_from_firebase(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(request): Json<FirebaseMigrationRequest>,
) -> Result<Json<MigrationResponse>, ApiError> {
    let service = MigrationService::new(state.db.clone(), state.redis.clone());

    let mut options = request.options.unwrap_or_default();
    options.dry_run = request.dry_run;

    let tenant_id = current_user.tenant_id.clone();
    let created_by = current_user.user_id.clone();
    let config = request.config;

    let result = service
        .migrate_from_firebase(
            &tenant_id,
            config.clone(),
            Some(options.clone()),
            Some(&created_by),
        )
        .await
        .map_err(|e| {
            tracing::error!("Failed to start Firebase migration: {}", e);
            ApiError::bad_request(format!("Failed to start migration: {}", e))
        })?;
    let job_id = result.job_id.clone();

    // Audit log
    let audit = AuditLogger::new(state.db.clone());
    audit.log(
        tenant_id.clone(),
        AuditAction::Custom("migration.firebase.started"),
        ResourceType::BulkJob,
        &job_id,
        Some(created_by),
        None,
        None,
        true,
        None,
        Some(serde_json::json!({
            "project_id": config.project_id,
            "dry_run": options.dry_run,
        })),
    );

    Ok(Json(MigrationResponse {
        id: job_id,
        source: "firebase".to_string(),
        status: "completed".to_string(),
        message: "Migration completed".to_string(),
        dry_run: Some(result.dry_run),
    }))
}

/// Migrate users from AWS Cognito
async fn migrate_from_cognito(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(request): Json<CognitoMigrationRequest>,
) -> Result<Json<MigrationResponse>, ApiError> {
    let service = MigrationService::new(state.db.clone(), state.redis.clone());

    let mut options = request.options.unwrap_or_default();
    options.dry_run = request.dry_run;

    let tenant_id = current_user.tenant_id.clone();
    let created_by = current_user.user_id.clone();
    let config = request.config;

    let result = service
        .migrate_from_cognito(
            &tenant_id,
            config.clone(),
            Some(options.clone()),
            Some(&created_by),
        )
        .await
        .map_err(|e| {
            tracing::error!("Failed to start Cognito migration: {}", e);
            ApiError::bad_request(format!("Failed to start migration: {}", e))
        })?;
    let job_id = result.job_id.clone();

    // Audit log
    let audit = AuditLogger::new(state.db.clone());
    audit.log(
        tenant_id.clone(),
        AuditAction::Custom("migration.cognito.started"),
        ResourceType::BulkJob,
        &job_id,
        Some(created_by),
        None,
        None,
        true,
        None,
        Some(serde_json::json!({
            "region": config.region,
            "user_pool_id": config.user_pool_id,
            "dry_run": options.dry_run,
        })),
    );

    Ok(Json(MigrationResponse {
        id: job_id,
        source: "cognito".to_string(),
        status: "completed".to_string(),
        message: "Migration completed".to_string(),
        dry_run: Some(result.dry_run),
    }))
}

/// Import users from CSV file
async fn migrate_from_csv(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    mut multipart: Multipart,
) -> Result<Json<MigrationResponse>, ApiError> {
    let mut csv_data: Option<Vec<u8>> = None;
    let mut config: Option<CsvConfig> = None;
    let mut options: Option<MigrationOptions> = None;
    let mut dry_run = false;

    // Parse multipart form
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| ApiError::bad_request(format!("Failed to parse form: {}", e)))?
    {
        let name = field.name().unwrap_or("").to_string();

        match name.as_str() {
            "file" => {
                csv_data = Some(
                    field
                        .bytes()
                        .await
                        .map_err(|e| ApiError::bad_request(format!("Failed to read file: {}", e)))?
                        .to_vec(),
                );
            }
            "config" => {
                let text = field
                    .text()
                    .await
                    .map_err(|e| ApiError::bad_request(format!("Failed to read config: {}", e)))?;
                config = Some(
                    serde_json::from_str(&text)
                        .map_err(|e| ApiError::bad_request(format!("Invalid config: {}", e)))?,
                );
            }
            "options" => {
                let text = field
                    .text()
                    .await
                    .map_err(|e| ApiError::bad_request(format!("Failed to read options: {}", e)))?;
                options = Some(
                    serde_json::from_str(&text)
                        .map_err(|e| ApiError::bad_request(format!("Invalid options: {}", e)))?,
                );
            }
            "dry_run" => {
                let text = field.text().await.unwrap_or_default();
                dry_run = text == "true";
            }
            _ => {}
        }
    }

    let csv_data = csv_data.ok_or_else(|| ApiError::bad_request("No file uploaded"))?;
    let config = config.unwrap_or_default();
    let mut options = options.unwrap_or_default();
    options.dry_run = dry_run;

    // Validate file size
    if csv_data.len() > MAX_CSV_SIZE {
        return Err(ApiError::bad_request(format!(
            "File too large. Maximum size is {}MB",
            MAX_CSV_SIZE / 1024 / 1024
        )));
    }

    let service = MigrationService::new(state.db.clone(), state.redis.clone());

    let tenant_id = current_user.tenant_id.clone();
    let created_by = current_user.user_id.clone();

    let result = service
        .import_from_csv(&tenant_id, &csv_data, config.clone(), Some(options), Some(&created_by))
        .await
        .map_err(|e| {
            tracing::error!("Failed to start CSV import: {}", e);
            ApiError::bad_request(format!("Failed to import: {}", e))
        })?;
    let job_id = result.job_id.clone();

    // Audit log
    let audit = AuditLogger::new(state.db.clone());
    audit.log(
        tenant_id.clone(),
        AuditAction::Custom("migration.csv.started"),
        ResourceType::BulkJob,
        &job_id,
        Some(created_by),
        None,
        None,
        true,
        None,
        Some(serde_json::json!({
            "file_size": csv_data.len(),
            "dry_run": dry_run,
        })),
    );

    Ok(Json(MigrationResponse {
        id: job_id,
        source: "csv".to_string(),
        status: "completed".to_string(),
        message: "Import completed".to_string(),
        dry_run: Some(result.dry_run),
    }))
}

/// Validate CSV file before import
async fn validate_csv(
    State(state): State<AppState>,
    Extension(_current_user): Extension<CurrentUser>,
    mut multipart: Multipart,
) -> Result<Json<ValidationResultResponse>, ApiError> {
    let mut csv_data: Option<Vec<u8>> = None;
    let mut config: Option<CsvConfig> = None;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| ApiError::bad_request(format!("Failed to parse form: {}", e)))?
    {
        let name = field.name().unwrap_or("").to_string();

        match name.as_str() {
            "file" => {
                csv_data = Some(
                    field
                        .bytes()
                        .await
                        .map_err(|e| ApiError::bad_request(format!("Failed to read file: {}", e)))?
                        .to_vec(),
                );
            }
            "config" => {
                let text = field
                    .text()
                    .await
                    .map_err(|e| ApiError::bad_request(format!("Failed to read config: {}", e)))?;
                config = Some(
                    serde_json::from_str(&text)
                        .map_err(|e| ApiError::bad_request(format!("Invalid config: {}", e)))?,
                );
            }
            _ => {}
        }
    }

    let csv_data = csv_data.ok_or_else(|| ApiError::bad_request("No file uploaded"))?;
    let config = config.unwrap_or_default();

    let service = MigrationService::new(state.db.clone(), state.redis.clone());

    let validation = service.validate_csv(&csv_data, &config);

    Ok(Json(ValidationResultResponse {
        valid: validation.valid,
        errors: validation.errors,
        warnings: validation.warnings,
    }))
}

/// Preview CSV import (show sample rows)
async fn preview_csv(
    State(_state): State<AppState>,
    Extension(_current_user): Extension<CurrentUser>,
    mut multipart: Multipart,
) -> Result<Json<CsvPreviewResponse>, ApiError> {
    let mut csv_data: Option<Vec<u8>> = None;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| ApiError::bad_request(format!("Failed to parse form: {}", e)))?
    {
        if field.name() == Some("file") {
            csv_data = Some(
                field
                    .bytes()
                    .await
                    .map_err(|e| ApiError::bad_request(format!("Failed to read file: {}", e)))?
                    .to_vec(),
            );
        }
    }

    let csv_data = csv_data.ok_or_else(|| ApiError::bad_request("No file uploaded"))?;

    // Detect format
    let detected_config =
        crate::migration::CsvImporter::detect_format(&csv_data).map_err(|e| {
            ApiError::bad_request(format!("Failed to detect format: {}", e))
        })?;

    // Parse sample (first 5 rows)
    let options = MigrationOptions::default();
    let (users, _errors) = crate::migration::CsvImporter::parse_users(
        &csv_data,
        &detected_config,
        "preview".to_string(),
        &options,
    )
    .map_err(|e| ApiError::bad_request(format!("Failed to parse CSV: {}", e)))?;

    let sample: Vec<CsvUserPreview> = users
        .into_iter()
        .take(5)
        .map(|u| CsvUserPreview {
            email: u.email,
            name: u
                .profile
                .as_ref()
                .and_then(|p| p.get("name").and_then(|n| n.as_str().map(String::from))),
            phone: u
                .profile
                .as_ref()
                .and_then(|p| p.get("phone_number").and_then(|p| p.as_str().map(String::from))),
            status: u.status,
        })
        .collect();

    let validation = crate::migration::CsvImporter::validate_csv(&csv_data, &detected_config);

    Ok(Json(CsvPreviewResponse {
        total_rows: sample.len(),
        sample,
        detected_config,
        validation_result: ValidationResultResponse {
            valid: validation.valid,
            errors: validation.errors,
            warnings: validation.warnings,
        },
    }))
}

/// List migration jobs
async fn list_migrations(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Query(query): Query<ListMigrationsQuery>,
) -> Result<Json<MigrationListResponse>, ApiError> {
    let service = MigrationService::new(state.db.clone(), state.redis.clone());

    let jobs = service
        .list_jobs(&current_user.tenant_id, query.limit, query.offset)
        .await
        .map_err(|e| {
            tracing::error!("Failed to list migrations: {}", e);
            ApiError::internal()
        })?;

    let migrations: Vec<MigrationDetailResponse> = jobs
        .into_iter()
        .map(|job| MigrationDetailResponse {
            id: job.id.clone(),
            source: job.source.as_str().to_string(),
            status: job.status.as_str().to_string(),
            total_users: job.total_users,
            processed: job.processed,
            succeeded: job.succeeded,
            failed: job.failed,
            dry_run: job.dry_run,
            percent_complete: if job.total_users > 0 {
                (job.processed as f64 / job.total_users as f64) * 100.0
            } else {
                0.0
            },
            started_at: job.started_at.to_rfc3339(),
            completed_at: job.completed_at.map(|d| d.to_rfc3339()),
            duration_secs: job.completed_at.map(|c| {
                (c - job.started_at).num_seconds()
            }),
            created_by: job.created_by,
        })
        .collect();

    Ok(Json(MigrationListResponse {
        total: migrations.len() as i64,
        migrations,
    }))
}

/// Get migration job details
async fn get_migration(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(id): Path<String>,
) -> Result<Json<MigrationDetailResponse>, ApiError> {
    let service = MigrationService::new(state.db.clone(), state.redis.clone());

    let job = service
        .get_job(&id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get migration: {}", e);
            ApiError::internal()
        })?
        .ok_or(ApiError::NotFound)?;

    // Verify tenant access
    if job.tenant_id != current_user.tenant_id {
        return Err(ApiError::Forbidden);
    }

    Ok(Json(MigrationDetailResponse {
        id: job.id.clone(),
        source: job.source.as_str().to_string(),
        status: job.status.as_str().to_string(),
        total_users: job.total_users,
        processed: job.processed,
        succeeded: job.succeeded,
        failed: job.failed,
        dry_run: job.dry_run,
        percent_complete: if job.total_users > 0 {
            (job.processed as f64 / job.total_users as f64) * 100.0
        } else {
            0.0
        },
        started_at: job.started_at.to_rfc3339(),
        completed_at: job.completed_at.map(|d| d.to_rfc3339()),
        duration_secs: job.completed_at.map(|c| {
            (c - job.started_at).num_seconds()
        }),
        created_by: job.created_by,
    }))
}

/// Get migration progress (for polling)
async fn get_migration_progress(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(id): Path<String>,
) -> Result<Json<ProgressResponse>, ApiError> {
    let service = MigrationService::new(state.db.clone(), state.redis.clone());

    let progress = service
        .get_progress(&id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get progress: {}", e);
            ApiError::internal()
        })?
        .ok_or(ApiError::NotFound)?;

    // Verify tenant access by checking job ownership
    if let Some(job) = service.get_job(&id).await.map_err(|_| ApiError::internal())? {
        if job.tenant_id != current_user.tenant_id {
            return Err(ApiError::Forbidden);
        }
    }

    let percent_complete = progress.percent_complete();
    let estimated_remaining_secs = progress.estimated_remaining_secs();

    Ok(Json(ProgressResponse {
        id: progress.id.clone(),
        source: progress.source.clone(),
        status: progress.status.as_str().to_string(),
        total_users: progress.total_users,
        processed: progress.processed,
        succeeded: progress.succeeded,
        failed: progress.failed,
        percent_complete,
        estimated_remaining_secs,
        current_operation: progress.current_operation.clone(),
    }))
}

/// Get migration errors
async fn get_migration_errors(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(id): Path<String>,
    Query(query): Query<ListMigrationsQuery>,
) -> Result<Json<ErrorResponse>, ApiError> {
    let service = MigrationService::new(state.db.clone(), state.redis.clone());

    // Verify tenant access
    if let Some(job) = service.get_job(&id).await.map_err(|_| ApiError::internal())? {
        if job.tenant_id != current_user.tenant_id {
            return Err(ApiError::Forbidden);
        }
    }

    let errors = service
        .get_errors(&id, query.limit, query.offset)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get errors: {}", e);
            ApiError::internal()
        })?;

    let error_details: Vec<ErrorDetail> = errors
        .into_iter()
        .map(|e| ErrorDetail {
            external_id: e.external_id,
            email: e.email,
            error: e.error_message,
            created_at: Some(e.created_at.to_rfc3339()),
        })
        .collect();

    Ok(Json(ErrorResponse {
        total: error_details.len() as i64,
        errors: error_details,
    }))
}

/// Cancel a migration
async fn cancel_migration(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(id): Path<String>,
) -> Result<Json<MigrationResponse>, ApiError> {
    let service = MigrationService::new(state.db.clone(), state.redis.clone());

    // Verify tenant access
    if let Some(job) = service.get_job(&id).await.map_err(|_| ApiError::internal())? {
        if job.tenant_id != current_user.tenant_id {
            return Err(ApiError::Forbidden);
        }
    }

    let cancelled = service.cancel_job(&id).await.map_err(|e| {
        tracing::error!("Failed to cancel migration: {}", e);
        ApiError::internal()
    })?;

    if !cancelled {
        return Err(ApiError::bad_request(
            "Migration cannot be cancelled (may already be completed or failed)",
        ));
    }

    // Audit log
    let audit = AuditLogger::new(state.db.clone());
    audit.log(
        current_user.tenant_id.clone(),
        AuditAction::Custom("migration.cancelled"),
        ResourceType::BulkJob,
        &id,
        Some(current_user.user_id),
        None,
        None,
        true,
        None,
        None,
    );

    Ok(Json(MigrationResponse {
        id,
        source: "".to_string(),
        status: "cancelled".to_string(),
        message: "Migration cancelled".to_string(),
        dry_run: None,
    }))
}

/// Resume a failed migration
async fn resume_migration(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(id): Path<String>,
) -> Result<Json<MigrationResponse>, ApiError> {
    let service = MigrationService::new(state.db.clone(), state.redis.clone());

    // Verify tenant access
    if let Some(job) = service.get_job(&id).await.map_err(|_| ApiError::internal())? {
        if job.tenant_id != current_user.tenant_id {
            return Err(ApiError::Forbidden);
        }
    }

    let new_job = service.resume_job(&id).await.map_err(|e| {
        tracing::error!("Failed to resume migration: {}", e);
        ApiError::bad_request(format!("Failed to resume: {}", e))
    })?;

    let new_job = new_job.ok_or_else(|| ApiError::bad_request("Migration cannot be resumed"))?;

    // Audit log
    let audit = AuditLogger::new(state.db.clone());
    audit.log(
        current_user.tenant_id.clone(),
        AuditAction::Custom("migration.resumed"),
        ResourceType::BulkJob,
        &new_job.id,
        Some(current_user.user_id),
        None,
        None,
        true,
        None,
        Some(serde_json::json!({
            "original_job_id": id,
        })),
    );

    Ok(Json(MigrationResponse {
        id: new_job.id,
        source: new_job.source.as_str().to_string(),
        status: "pending".to_string(),
        message: "Migration resumed".to_string(),
        dry_run: Some(new_job.dry_run),
    }))
}

/// Pause a running migration
async fn pause_migration(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(id): Path<String>,
) -> Result<Json<MigrationResponse>, ApiError> {
    let service = MigrationService::new(state.db.clone(), state.redis.clone());

    // Verify tenant access
    if let Some(job) = service.get_job(&id).await.map_err(|_| ApiError::internal())? {
        if job.tenant_id != current_user.tenant_id {
            return Err(ApiError::Forbidden);
        }
    }

    let paused = service.pause_job(&id).await.map_err(|e| {
        tracing::error!("Failed to pause migration: {}", e);
        ApiError::internal()
    })?;

    if !paused {
        return Err(ApiError::bad_request(
            "Migration cannot be paused (may not be running)",
        ));
    }

    Ok(Json(MigrationResponse {
        id,
        source: "".to_string(),
        status: "paused".to_string(),
        message: "Migration paused".to_string(),
        dry_run: None,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_limit() {
        assert_eq!(default_limit(), 20);
    }
}
