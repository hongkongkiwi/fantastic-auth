//! User migration service for importing users from external identity providers
//!
//! Supports:
//! - Auth0
//! - Firebase Authentication
//! - AWS Cognito
//! - CSV import
//!
//! # Example Usage
//!
//! ```rust
//! use vault_server::migration::{MigrationService, Auth0Config};
//!
//! async fn migrate_from_auth0() {
//!     let service = MigrationService::new(db, redis);
//!     
//!     let config = Auth0Config {
//!         domain: "myapp.auth0.com".to_string(),
//!         client_id: "client_id".to_string(),
//!         client_secret: "secret".to_string(),
//!         connection: None,
//!         import_passwords: false,
//!         audience: None,
//!     };
//!
//!     let result = service.migrate_from_auth0(config).await.unwrap();
//!     println!("Migrated {}/{} users", result.migrated, result.total);
//! }
//! ```

use chrono::Utc;
use std::sync::Arc;
use tokio::sync::RwLock;

mod auth0;
mod cognito;
mod csv_importer;
mod firebase;
mod models;
mod progress;

pub use auth0::{Auth0Config, Auth0Migrator, Auth0User};
pub use cognito::{CognitoConfig, CognitoMigrator, CognitoUser};
pub use csv_importer::{CsvConfig, CsvImporter};
pub use firebase::{FirebaseConfig, FirebaseMigrator, FirebaseUser};
pub use models::{
    CreateUserFromMigration, ExternalUser, MigrationError, MigrationJob, MigrationOptions,
    MigrationProgress, MigrationResult, MigrationSource, MigrationStatus, TokenBucket,
    ValidationResult,
};
pub use progress::{MigrationBackgroundExecutor, ProgressTracker};

use crate::db::Database;

/// Migration service coordinator
pub struct MigrationService {
    db: Database,
    redis: Option<redis::aio::ConnectionManager>,
    tracker: ProgressTracker,
    active_jobs: Arc<RwLock<Vec<String>>>,
    default_options: MigrationOptions,
}

impl MigrationService {
    /// Create a new migration service
    pub fn new(db: Database, redis: Option<redis::aio::ConnectionManager>) -> Self {
        let pool = db.pool();
        let tracker = ProgressTracker::new(redis.clone(), Some(pool.clone()));

        Self {
            db,
            redis,
            tracker,
            active_jobs: Arc::new(RwLock::new(Vec::new())),
            default_options: MigrationOptions::default(),
        }
    }

    /// Set default migration options
    pub fn with_options(mut self, options: MigrationOptions) -> Self {
        self.default_options = options;
        self
    }

    /// Migrate users from Auth0
    pub async fn migrate_from_auth0(
        &self,
        tenant_id: &str,
        config: Auth0Config,
        options: Option<MigrationOptions>,
        created_by: Option<&str>,
    ) -> anyhow::Result<MigrationResult> {
        let options = options.unwrap_or_else(|| self.default_options.clone());

        // Create migrator and validate connection
        let migrator = Auth0Migrator::new(config.clone()).await?;

        // Get user count for progress tracking
        let total_users = migrator.get_user_count().await? as usize;

        // Create migration job
        let job_id = self
            .tracker
            .create_job(
                tenant_id,
                MigrationSource::Auth0,
                total_users,
                serde_json::to_value(&config)?,
                created_by,
                options.dry_run,
            )
            .await?;

        // Track as active job
        self.active_jobs.write().await.push(job_id.clone());

        // Start migration
        let result = self
            .run_auth0_migration(&job_id, tenant_id, migrator, &options)
            .await;

        // Remove from active jobs
        self.active_jobs.write().await.retain(|id| id != &job_id);

        result
    }

    /// Run the actual Auth0 migration
    async fn run_auth0_migration(
        &self,
        job_id: &str,
        tenant_id: &str,
        migrator: Auth0Migrator,
        options: &MigrationOptions,
    ) -> anyhow::Result<MigrationResult> {
        use futures::StreamExt;

        let mut result = MigrationResult::new(job_id.to_string(), options.dry_run);
        let start_time = std::time::Instant::now();

        // Update status to running
        self.tracker
            .update_status(job_id, MigrationStatus::Running)
            .await?;

        let batch_size = options.batch_size;
        let mut token_bucket = TokenBucket::new(
            10.0, // 10 requests per second
            100.0,
        );

        // Process users in batches
        let stream = migrator.stream_users(batch_size).await?;
        let mut stream = Box::pin(stream);

        while let Some(user_result) = stream.next().await {
            // Rate limiting
            token_bucket.acquire(1.0).await;

            match user_result {
                Ok(auth0_user) => {
                    let external_user = migrator.convert_to_external_user(auth0_user.clone());

                    // Validate user
                    let validation = migrator.validate_user(&auth0_user, options);
                    if !validation.valid {
                        result.add_failure(MigrationError {
                            user_id: external_user.external_id.clone(),
                            email: external_user.email.clone(),
                            error: validation.errors.join(", "),
                            details: Some(serde_json::json!({
                                "warnings": validation.warnings
                            })),
                        });
                        continue;
                    }

                    // Check if user already exists
                    if options.skip_existing {
                        if let Some(ref email) = external_user.email {
                            if self.user_exists(tenant_id, email).await? {
                                result.add_skipped();
                                continue;
                            }
                        }
                    }

                    if options.dry_run {
                        result.add_success();
                    } else {
                        // Create user
                        let create_request = auth0::convert_to_vault_request(
                            external_user.clone(),
                            tenant_id.to_string(),
                            options,
                        );

                        match self.create_user(create_request).await {
                            Ok(_) => {
                                result.add_success();
                            }
                            Err(e) => {
                                let error = MigrationError {
                                    user_id: external_user.external_id.clone(),
                                    email: external_user.email.clone(),
                                    error: e.to_string(),
                                    details: None,
                                };
                                self.tracker.record_error(job_id, &error).await?;
                                result.add_failure(error);
                            }
                        }
                    }

                    // Update progress every 10 users
                    if result.migrated % 10 == 0 {
                        self.tracker
                            .update_progress(
                                job_id,
                                result.migrated + result.failed + result.skipped,
                                result.migrated,
                                result.failed,
                                Some("Processing users"),
                            )
                            .await?;
                    }
                }
                Err(error) => {
                    result.add_failure(error.clone());
                    self.tracker.record_error(job_id, &error).await?;
                }
            }
        }

        // Final progress update
        self.tracker
            .update_progress(
                job_id,
                result.migrated + result.failed + result.skipped,
                result.migrated,
                result.failed,
                Some("Completed"),
            )
            .await?;

        // Update final status
        let final_status = if result.failed == result.total && result.total > 0 {
            MigrationStatus::Failed
        } else {
            MigrationStatus::Completed
        };

        self.tracker.update_status(job_id, final_status).await?;

        result.total = result.migrated + result.failed + result.skipped;
        result.duration_secs = start_time.elapsed().as_secs();

        Ok(result)
    }

    /// Migrate users from Firebase
    pub async fn migrate_from_firebase(
        &self,
        tenant_id: &str,
        config: FirebaseConfig,
        options: Option<MigrationOptions>,
        created_by: Option<&str>,
    ) -> anyhow::Result<MigrationResult> {
        let options = options.unwrap_or_else(|| self.default_options.clone());

        // Create migrator and validate connection
        let migrator = FirebaseMigrator::new(config.clone()).await?;

        // Create migration job (Firebase doesn't give us total count upfront)
        let job_id = self
            .tracker
            .create_job(
                tenant_id,
                MigrationSource::Firebase,
                0, // Unknown until we start
                serde_json::to_value(&config)?,
                created_by,
                options.dry_run,
            )
            .await?;

        self.active_jobs.write().await.push(job_id.clone());

        let result = self
            .run_firebase_migration(&job_id, tenant_id, migrator, &options)
            .await;

        self.active_jobs.write().await.retain(|id| id != &job_id);

        result
    }

    /// Run the actual Firebase migration
    async fn run_firebase_migration(
        &self,
        job_id: &str,
        tenant_id: &str,
        migrator: FirebaseMigrator,
        options: &MigrationOptions,
    ) -> anyhow::Result<MigrationResult> {
        use futures::StreamExt;

        let mut result = MigrationResult::new(job_id.to_string(), options.dry_run);
        let start_time = std::time::Instant::now();

        self.tracker
            .update_status(job_id, MigrationStatus::Running)
            .await?;

        let batch_size = options.batch_size;
        let mut token_bucket = TokenBucket::new(10.0, 100.0);

        let mut stream = migrator.stream_users(batch_size).await?;

        while let Some(user_result) = stream.next().await {
            token_bucket.acquire(1.0).await;

            match user_result {
                Ok(fb_user) => {
                    let external_user = migrator.convert_to_external_user(fb_user.clone());

                    let validation = migrator.validate_user(&fb_user, options);
                    if !validation.valid {
                        result.add_failure(MigrationError {
                            user_id: external_user.external_id.clone(),
                            email: external_user.email.clone(),
                            error: validation.errors.join(", "),
                            details: Some(serde_json::json!({
                                "warnings": validation.warnings
                            })),
                        });
                        continue;
                    }

                    if options.skip_existing {
                        if let Some(ref email) = external_user.email {
                            if self.user_exists(tenant_id, email).await? {
                                result.add_skipped();
                                continue;
                            }
                        }
                    }

                    if options.dry_run {
                        result.add_success();
                    } else {
                        let create_request = firebase::convert_to_vault_request(
                            external_user.clone(),
                            tenant_id.to_string(),
                            options,
                        );

                        match self.create_user(create_request).await {
                            Ok(_) => {
                                result.add_success();
                            }
                            Err(e) => {
                                let error = MigrationError {
                                    user_id: external_user.external_id.clone(),
                                    email: external_user.email.clone(),
                                    error: e.to_string(),
                                    details: None,
                                };
                                self.tracker.record_error(job_id, &error).await?;
                                result.add_failure(error);
                            }
                        }
                    }

                    if result.migrated % 10 == 0 {
                        self.tracker
                            .update_progress(
                                job_id,
                                result.migrated + result.failed + result.skipped,
                                result.migrated,
                                result.failed,
                                Some("Processing users"),
                            )
                            .await?;
                    }
                }
                Err(error) => {
                    result.add_failure(error.clone());
                    self.tracker.record_error(job_id, &error).await?;
                }
            }
        }

        self.tracker
            .update_progress(
                job_id,
                result.migrated + result.failed + result.skipped,
                result.migrated,
                result.failed,
                Some("Completed"),
            )
            .await?;

        let final_status = if result.failed == result.total && result.total > 0 {
            MigrationStatus::Failed
        } else {
            MigrationStatus::Completed
        };

        self.tracker.update_status(job_id, final_status).await?;

        result.total = result.migrated + result.failed + result.skipped;
        result.duration_secs = start_time.elapsed().as_secs();

        Ok(result)
    }

    /// Migrate users from AWS Cognito
    pub async fn migrate_from_cognito(
        &self,
        tenant_id: &str,
        config: CognitoConfig,
        options: Option<MigrationOptions>,
        created_by: Option<&str>,
    ) -> anyhow::Result<MigrationResult> {
        let options = options.unwrap_or_else(|| self.default_options.clone());

        // Create migrator
        let migrator = CognitoMigrator::new(config.clone())?;

        // Create migration job
        let job_id = self
            .tracker
            .create_job(
                tenant_id,
                MigrationSource::Cognito,
                0, // Unknown until we start
                serde_json::to_value(&config)?,
                created_by,
                options.dry_run,
            )
            .await?;

        self.active_jobs.write().await.push(job_id.clone());

        let result = self
            .run_cognito_migration(&job_id, tenant_id, migrator, &options)
            .await;

        self.active_jobs.write().await.retain(|id| id != &job_id);

        result
    }

    /// Run the actual Cognito migration
    async fn run_cognito_migration(
        &self,
        job_id: &str,
        tenant_id: &str,
        migrator: CognitoMigrator,
        options: &MigrationOptions,
    ) -> anyhow::Result<MigrationResult> {
        use futures::StreamExt;

        let mut result = MigrationResult::new(job_id.to_string(), options.dry_run);
        let start_time = std::time::Instant::now();

        self.tracker
            .update_status(job_id, MigrationStatus::Running)
            .await?;

        let batch_size = options.batch_size;
        let mut token_bucket = TokenBucket::new(10.0, 100.0);

        let mut stream = migrator.stream_users(batch_size).await?;

        while let Some(user_result) = stream.next().await {
            token_bucket.acquire(1.0).await;

            match user_result {
                Ok(cognito_user) => {
                    let external_user = migrator.convert_to_external_user(cognito_user.clone());

                    let validation = migrator.validate_user(&cognito_user, options);
                    if !validation.valid {
                        result.add_failure(MigrationError {
                            user_id: external_user.external_id.clone(),
                            email: external_user.email.clone(),
                            error: validation.errors.join(", "),
                            details: Some(serde_json::json!({
                                "warnings": validation.warnings
                            })),
                        });
                        continue;
                    }

                    if options.skip_existing {
                        if let Some(ref email) = external_user.email {
                            if self.user_exists(tenant_id, email).await? {
                                result.add_skipped();
                                continue;
                            }
                        }
                    }

                    if options.dry_run {
                        result.add_success();
                    } else {
                        let create_request = cognito::convert_to_vault_request(
                            external_user.clone(),
                            tenant_id.to_string(),
                            options,
                        );

                        match self.create_user(create_request).await {
                            Ok(_) => {
                                result.add_success();
                            }
                            Err(e) => {
                                let error = MigrationError {
                                    user_id: external_user.external_id.clone(),
                                    email: external_user.email.clone(),
                                    error: e.to_string(),
                                    details: None,
                                };
                                self.tracker.record_error(job_id, &error).await?;
                                result.add_failure(error);
                            }
                        }
                    }

                    if result.migrated % 10 == 0 {
                        self.tracker
                            .update_progress(
                                job_id,
                                result.migrated + result.failed + result.skipped,
                                result.migrated,
                                result.failed,
                                Some("Processing users"),
                            )
                            .await?;
                    }
                }
                Err(error) => {
                    result.add_failure(error.clone());
                    self.tracker.record_error(job_id, &error).await?;
                }
            }
        }

        self.tracker
            .update_progress(
                job_id,
                result.migrated + result.failed + result.skipped,
                result.migrated,
                result.failed,
                Some("Completed"),
            )
            .await?;

        let final_status = if result.failed == result.total && result.total > 0 {
            MigrationStatus::Failed
        } else {
            MigrationStatus::Completed
        };

        self.tracker.update_status(job_id, final_status).await?;

        result.total = result.migrated + result.failed + result.skipped;
        result.duration_secs = start_time.elapsed().as_secs();

        Ok(result)
    }

    /// Import users from CSV
    pub async fn import_from_csv(
        &self,
        tenant_id: &str,
        csv_data: &[u8],
        config: CsvConfig,
        options: Option<MigrationOptions>,
        created_by: Option<&str>,
    ) -> anyhow::Result<MigrationResult> {
        let options = options.unwrap_or_else(|| self.default_options.clone());

        // Parse CSV to get user count
        let (parsed_users, parse_errors) =
            CsvImporter::parse_users(csv_data, &config, tenant_id.to_string(), &options)?;

        // Create migration job
        let job_id = self
            .tracker
            .create_job(
                tenant_id,
                MigrationSource::Csv,
                parsed_users.len(),
                serde_json::to_value(&config)?,
                created_by,
                options.dry_run,
            )
            .await?;

        self.active_jobs.write().await.push(job_id.clone());

        let result = self
            .run_csv_import(&job_id, tenant_id, parsed_users, parse_errors, &options)
            .await;

        self.active_jobs.write().await.retain(|id| id != &job_id);

        result
    }

    /// Run the actual CSV import
    async fn run_csv_import(
        &self,
        job_id: &str,
        tenant_id: &str,
        users: Vec<CreateUserFromMigration>,
        mut parse_errors: Vec<MigrationError>,
        options: &MigrationOptions,
    ) -> anyhow::Result<MigrationResult> {
        let mut result = MigrationResult::new(job_id.to_string(), options.dry_run);
        let start_time = std::time::Instant::now();

        self.tracker
            .update_status(job_id, MigrationStatus::Running)
            .await?;

        // Add parse errors to result
        for error in parse_errors.drain(..) {
            self.tracker.record_error(job_id, &error).await?;
            result.add_failure(error);
        }

        let total = users.len();

        for (idx, user) in users.into_iter().enumerate() {
            if options.skip_existing && self.user_exists(tenant_id, &user.email).await? {
                result.add_skipped();
                continue;
            }

            if options.dry_run {
                result.add_success();
            } else {
                match self.create_user(user).await {
                    Ok(_) => {
                        result.add_success();
                    }
                    Err(e) => {
                        let error = MigrationError {
                            user_id: format!("csv_row_{}", idx),
                            email: None,
                            error: e.to_string(),
                            details: None,
                        };
                        self.tracker.record_error(job_id, &error).await?;
                        result.add_failure(error);
                    }
                }
            }

            if idx % 10 == 0 {
                self.tracker
                    .update_progress(
                        job_id,
                        result.migrated + result.failed + result.skipped,
                        result.migrated,
                        result.failed,
                        Some("Processing users"),
                    )
                    .await?;
            }
        }

        self.tracker
            .update_progress(
                job_id,
                result.migrated + result.failed + result.skipped,
                result.migrated,
                result.failed,
                Some("Completed"),
            )
            .await?;

        let final_status = if result.failed == result.total && result.total > 0 {
            MigrationStatus::Failed
        } else {
            MigrationStatus::Completed
        };

        self.tracker.update_status(job_id, final_status).await?;

        result.total = total;
        result.duration_secs = start_time.elapsed().as_secs();

        Ok(result)
    }

    /// Check if a user exists by email
    async fn user_exists(&self, tenant_id: &str, email: &str) -> anyhow::Result<bool> {
        let pool = self.db.pool();

        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM users WHERE tenant_id = $1::uuid AND email = $2 AND deleted_at IS NULL"
        )
        .bind(tenant_id)
        .bind(email.to_lowercase())
        .fetch_one(pool)
        .await?;

        Ok(count > 0)
    }

    /// Create a user from migration data
    async fn create_user(
        &self,
        request: CreateUserFromMigration,
    ) -> anyhow::Result<vault_core::models::user::User> {
        use std::sync::Arc;
        use vault_core::db::users::{CreateUserRequest, UserRepository};

        let repo = UserRepository::new(Arc::new(self.db.pool().clone()));

        let create_req = CreateUserRequest {
            tenant_id: request.tenant_id,
            email: request.email,
            password_hash: request.password_hash,
            email_verified: request.email_verified,
            profile: request.profile,
            metadata: request.metadata,
        };

        let user = repo.create(create_req).await?;
        Ok(user)
    }

    /// Get migration progress
    pub async fn get_progress(&self, job_id: &str) -> anyhow::Result<Option<MigrationProgress>> {
        self.tracker.get_progress(job_id).await
    }

    /// Get migration job details
    pub async fn get_job(&self, job_id: &str) -> anyhow::Result<Option<MigrationJob>> {
        let pool = self.db.pool();

        let job: Option<MigrationJob> = sqlx::query_as(
            r#"SELECT 
                id, tenant_id, source, status, total_users, processed, 
                succeeded, failed, config, dry_run, started_at, completed_at, 
                created_by, resumed_from, last_processed_id
               FROM migration_jobs WHERE id = $1"#,
        )
        .bind(job_id)
        .fetch_optional(pool)
        .await?;

        Ok(job)
    }

    /// Get migration errors
    pub async fn get_errors(
        &self,
        job_id: &str,
        limit: usize,
        offset: usize,
    ) -> anyhow::Result<Vec<models::MigrationErrorRecord>> {
        self.tracker.get_errors(job_id, limit, offset).await
    }

    /// List migration jobs for a tenant
    pub async fn list_jobs(
        &self,
        tenant_id: &str,
        limit: usize,
        offset: usize,
    ) -> anyhow::Result<Vec<MigrationJob>> {
        self.tracker.list_jobs(tenant_id, limit, offset).await
    }

    /// Cancel a migration job
    pub async fn cancel_job(&self, job_id: &str) -> anyhow::Result<bool> {
        self.tracker.cancel_job(job_id).await
    }

    /// Resume a failed migration job
    pub async fn resume_job(&self, job_id: &str) -> anyhow::Result<Option<MigrationJob>> {
        self.tracker.resume_job(job_id).await
    }

    /// Validate CSV data before import
    pub fn validate_csv(&self, data: &[u8], config: &CsvConfig) -> ValidationResult {
        CsvImporter::validate_csv(data, config)
    }

    /// Detect CSV format from data
    pub fn detect_csv_format(data: &[u8]) -> anyhow::Result<CsvConfig> {
        CsvImporter::detect_format(data)
    }

    /// Get active migration jobs
    pub async fn get_active_jobs(&self) -> Vec<String> {
        self.active_jobs.read().await.clone()
    }

    /// Pause a running migration job
    pub async fn pause_job(&self, job_id: &str) -> anyhow::Result<bool> {
        // Get current job status
        if let Some(job) = self.get_job(job_id).await? {
            if job.status != MigrationStatus::Running {
                return Ok(false);
            }

            self.tracker
                .update_status(job_id, MigrationStatus::Paused)
                .await?;

            return Ok(true);
        }

        Ok(false)
    }
}

/// Create migration routes
pub fn routes() -> axum::Router<crate::state::AppState> {
    crate::routes::admin::migrations::routes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_migration_result_calculations() {
        let job_id = "job-123";
        let mut result = MigrationResult::new(job_id.to_string(), false);
        result.total = 100;
        result.migrated = 75;
        result.failed = 20;
        result.skipped = 5;

        assert_eq!(result.success_rate(), 75.0);
        assert_eq!(result.migrated, 75);
        assert_eq!(result.failed, 20);
        assert_eq!(result.skipped, 5);
    }
}
