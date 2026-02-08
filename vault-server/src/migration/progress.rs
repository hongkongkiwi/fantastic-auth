//! Migration progress tracking with Redis support

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::time::timeout;

use crate::migration::models::{
    MigrationError, MigrationErrorRecord, MigrationJob, MigrationProgress, MigrationSource,
    MigrationStatus,
};

/// Progress tracker for migration jobs
pub struct ProgressTracker {
    redis: Option<redis::aio::ConnectionManager>,
    db: Option<sqlx::PgPool>,
}

impl ProgressTracker {
    /// Create a new progress tracker
    pub fn new(redis: Option<redis::aio::ConnectionManager>, db: Option<sqlx::PgPool>) -> Self {
        Self { redis, db }
    }

    /// Create a new migration job
    pub async fn create_job(
        &self,
        tenant_id: &str,
        source: MigrationSource,
        total_users: usize,
        config: serde_json::Value,
        created_by: Option<&str>,
        dry_run: bool,
    ) -> anyhow::Result<String> {
        let id = uuid::Uuid::new_v4().to_string();

        // Store in database
        if let Some(ref pool) = self.db {
            sqlx::query(
                r#"INSERT INTO migration_jobs (
                    id, tenant_id, source, status, total_users, config, 
                    created_by, dry_run, started_at
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())"#,
            )
            .bind(&id)
            .bind(tenant_id)
            .bind(source)
            .bind(MigrationStatus::Pending)
            .bind(total_users as i32)
            .bind(config)
            .bind(created_by)
            .bind(dry_run)
            .execute(pool)
            .await?;
        }

        // Cache in Redis for fast access
        if let Some(ref redis) = self.redis {
            let progress = MigrationProgress {
                id: id.clone(),
                source: source.as_str().to_string(),
                status: MigrationStatus::Pending,
                total_users,
                processed: 0,
                succeeded: 0,
                failed: 0,
                percent_complete: 0.0,
                estimated_remaining_secs: None,
                current_operation: Some("Initializing".to_string()),
                started_at: Utc::now(),
                completed_at: None,
                errors_count: 0,
            };

            let key = format!("migration:progress:{}", id);
            let value = serde_json::to_string(&progress)?;
            let mut conn = redis.clone();
            redis::cmd("SETEX")
                .arg(&key)
                .arg(86400) // 24 hour expiry
                .arg(&value)
                .query_async::<_, ()>(&mut conn)
                .await?;
        }

        Ok(id)
    }

    /// Update job progress
    pub async fn update_progress(
        &self,
        job_id: &str,
        processed: usize,
        succeeded: usize,
        failed: usize,
        current_operation: Option<&str>,
    ) -> anyhow::Result<()> {
        // Update database
        if let Some(ref pool) = self.db {
            sqlx::query(
                r#"UPDATE migration_jobs 
                   SET processed = $1, succeeded = $2, failed = $3
                   WHERE id = $4"#,
            )
            .bind(processed as i32)
            .bind(succeeded as i32)
            .bind(failed as i32)
            .bind(job_id)
            .execute(pool)
            .await?;
        }

        // Update Redis cache
        if let Some(ref redis) = self.redis {
            let key = format!("migration:progress:{}", job_id);
            let mut conn = redis.clone();

            // Get existing progress
            let existing: Option<String> = redis::cmd("GET")
                .arg(&key)
                .query_async(&mut conn)
                .await?;

            if let Some(json) = existing {
                let mut progress: MigrationProgress = serde_json::from_str(&json)?;
                progress.processed = processed;
                progress.succeeded = succeeded;
                progress.failed = failed;
                progress.percent_complete = if progress.total_users > 0 {
                    (processed as f64 / progress.total_users as f64) * 100.0
                } else {
                    0.0
                };

                if let Some(op) = current_operation {
                    progress.current_operation = Some(op.to_string());
                }

                // Update estimated remaining time
                if progress.status == MigrationStatus::Running && processed > 0 {
                    let elapsed = Utc::now().signed_duration_since(progress.started_at);
                    let elapsed_secs = elapsed.num_seconds().max(1) as f64;
                    let rate = processed as f64 / elapsed_secs;
                    let remaining = progress.total_users.saturating_sub(processed) as f64 / rate;
                    progress.estimated_remaining_secs = Some(remaining as u64);
                }

                let value = serde_json::to_string(&progress)?;
                redis::cmd("SETEX")
                    .arg(&key)
                    .arg(86400)
                    .arg(&value)
                    .query_async::<_, ()>(&mut conn)
                    .await?;
            }
        }

        Ok(())
    }

    /// Update job status
    pub async fn update_status(
        &self,
        job_id: &str,
        status: MigrationStatus,
    ) -> anyhow::Result<()> {
        // Update database
        if let Some(ref pool) = self.db {
            let completed_at = if status.is_terminal() {
                Some(Utc::now())
            } else {
                None
            };

            sqlx::query(
                r#"UPDATE migration_jobs 
                   SET status = $1, completed_at = $2
                   WHERE id = $3"#,
            )
            .bind(status)
            .bind(completed_at)
            .bind(job_id)
            .execute(pool)
            .await?;
        }

        // Update Redis cache
        if let Some(ref redis) = self.redis {
            let key = format!("migration:progress:{}", job_id);
            let mut conn = redis.clone();

            let existing: Option<String> = redis::cmd("GET")
                .arg(&key)
                .query_async(&mut conn)
                .await?;

            if let Some(json) = existing {
                let mut progress: MigrationProgress = serde_json::from_str(&json)?;
                progress.status = status;

                if status.is_terminal() {
                    progress.completed_at = Some(Utc::now());
                    progress.current_operation = None;
                    progress.estimated_remaining_secs = None;
                } else if status == MigrationStatus::Running {
                    progress.current_operation = Some("Processing users".to_string());
                }

                let value = serde_json::to_string(&progress)?;
                redis::cmd("SETEX")
                    .arg(&key)
                    .arg(86400)
                    .arg(&value)
                    .query_async::<_, ()>(&mut conn)
                    .await?;
            }
        }

        Ok(())
    }

    /// Get job progress
    pub async fn get_progress(&self, job_id: &str) -> anyhow::Result<Option<MigrationProgress>> {
        // Try Redis first for fast access
        if let Some(ref redis) = self.redis {
            let key = format!("migration:progress:{}", job_id);
            let mut conn = redis.clone();

            let value: Option<String> = redis::cmd("GET")
                .arg(&key)
                .query_async(&mut conn)
                .await?;

            if let Some(json) = value {
                let progress: MigrationProgress = serde_json::from_str(&json)?;
                return Ok(Some(progress));
            }
        }

        // Fall back to database
        if let Some(ref pool) = self.db {
            let row = sqlx::query(
                r#"SELECT 
                    id, tenant_id, source, status, total_users, processed, 
                    succeeded, failed, config, dry_run, started_at, completed_at, 
                    created_by, resumed_from, last_processed_id
                   FROM migration_jobs WHERE id = $1"#,
            )
            .bind(job_id)
            .fetch_optional(pool)
            .await?;

            if let Some(row) = row {
                use sqlx::Row;
                let total_users: i32 = row.try_get("total_users")?;
                let processed: i32 = row.try_get("processed")?;
                let failed: i32 = row.try_get("failed")?;
                let progress = MigrationProgress {
                    id: row.try_get("id")?,
                    source: row.try_get::<String, _>("source")?,
                    status: row.try_get("status")?,
                    total_users: total_users as usize,
                    processed: processed as usize,
                    succeeded: row.try_get::<i32, _>("succeeded")? as usize,
                    failed: failed as usize,
                    percent_complete: if total_users > 0 {
                        (processed as f64 / total_users as f64) * 100.0
                    } else {
                        0.0
                    },
                    estimated_remaining_secs: None,
                    current_operation: None,
                    started_at: row.try_get("started_at")?,
                    completed_at: row.try_get("completed_at")?,
                    errors_count: failed as usize,
                };
                return Ok(Some(progress));
            }
        }

        Ok(None)
    }

    /// Record an error
    pub async fn record_error(&self, job_id: &str, error: &MigrationError) -> anyhow::Result<()> {
        // Store in database
        if let Some(ref pool) = self.db {
            let error_id = uuid::Uuid::new_v4().to_string();

            sqlx::query(
                r#"INSERT INTO migration_errors (
                    id, migration_id, external_id, email, error_message, error_details
                ) VALUES ($1, $2, $3, $4, $5, $6)"#,
            )
            .bind(&error_id)
            .bind(job_id)
            .bind(&error.user_id)
            .bind(&error.email)
            .bind(&error.error)
            .bind(&error.details)
            .execute(pool)
            .await?;
        }

        // Increment error count in Redis
        if let Some(ref redis) = self.redis {
            let key = format!("migration:errors:{}", job_id);
            let mut conn = redis.clone();
            redis::cmd("LPUSH")
                .arg(&key)
                .arg(serde_json::to_string(error)?)
                .query_async::<_, ()>(&mut conn)
                .await?;

            // Set expiry
            redis::cmd("EXPIRE")
                .arg(&key)
                .arg(86400)
                .query_async::<_, ()>(&mut conn)
                .await?;
        }

        Ok(())
    }

    /// Get errors for a job
    pub async fn get_errors(
        &self,
        job_id: &str,
        limit: usize,
        offset: usize,
    ) -> anyhow::Result<Vec<MigrationErrorRecord>> {
        // Try database first
        if let Some(ref pool) = self.db {
            let errors: Vec<MigrationErrorRecord> = sqlx::query_as(
                r#"SELECT id, migration_id, external_id, email, error_message, error_details, created_at
                   FROM migration_errors 
                   WHERE migration_id = $1
                   ORDER BY created_at DESC
                   LIMIT $2 OFFSET $3"#,
            )
            .bind(job_id)
            .bind(limit as i64)
            .bind(offset as i64)
            .fetch_all(pool)
            .await?;

            return Ok(errors);
        }

        // Fall back to Redis
        if let Some(ref redis) = self.redis {
            let key = format!("migration:errors:{}", job_id);
            let mut conn = redis.clone();

            let errors: Vec<String> = redis::cmd("LRANGE")
                .arg(&key)
                .arg(offset as isize)
                .arg((offset + limit) as isize)
                .query_async(&mut conn)
                .await?;

            let mut result = Vec::new();
            for (idx, error_json) in errors.iter().enumerate() {
                if let Ok(error) = serde_json::from_str::<MigrationError>(error_json) {
                    result.push(MigrationErrorRecord {
                        id: format!("{}-{}", job_id, idx),
                        migration_id: job_id.to_string(),
                        external_id: Some(error.user_id),
                        email: error.email,
                        error_message: error.error,
                        error_details: error.details,
                        created_at: Utc::now(),
                    });
                }
            }

            return Ok(result);
        }

        Ok(Vec::new())
    }

    /// List jobs for a tenant
    pub async fn list_jobs(
        &self,
        tenant_id: &str,
        limit: usize,
        offset: usize,
    ) -> anyhow::Result<Vec<MigrationJob>> {
        if let Some(ref pool) = self.db {
            let jobs: Vec<MigrationJob> = sqlx::query_as(
                r#"SELECT 
                    id, tenant_id, source, status, total_users, processed, 
                    succeeded, failed, config, dry_run, started_at, completed_at, 
                    created_by, resumed_from, last_processed_id
                   FROM migration_jobs 
                   WHERE tenant_id = $1
                   ORDER BY started_at DESC
                   LIMIT $2 OFFSET $3"#,
            )
            .bind(tenant_id)
            .bind(limit as i64)
            .bind(offset as i64)
            .fetch_all(pool)
            .await?;

            return Ok(jobs);
        }

        Ok(Vec::new())
    }

    /// Resume a job
    pub async fn resume_job(&self, job_id: &str) -> anyhow::Result<Option<MigrationJob>> {
        // Get the job
        if let Some(ref pool) = self.db {
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

            if let Some(mut job) = job {
                // Can only resume failed or paused jobs
                if !matches!(job.status, MigrationStatus::Failed | MigrationStatus::Paused) {
                    return Err(anyhow::anyhow!(
                        "Cannot resume job with status {:?}",
                        job.status
                    ));
                }

                // Create a new job that resumes from this one
                let new_job_id = uuid::Uuid::new_v4().to_string();

                sqlx::query(
                    r#"INSERT INTO migration_jobs (
                        id, tenant_id, source, status, total_users, config, 
                        created_by, dry_run, resumed_from
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"#,
                )
                .bind(&new_job_id)
                .bind(&job.tenant_id)
                .bind(job.source)
                .bind(MigrationStatus::Pending)
                .bind(job.total_users - job.processed)
                .bind(&job.config)
                .bind(&job.created_by)
                .bind(job.dry_run)
                .bind(job_id)
                .execute(pool)
                .await?;

                // Get the new job
                let new_job: Option<MigrationJob> = sqlx::query_as(
                    r#"SELECT 
                        id, tenant_id, source, status, total_users, processed, 
                        succeeded, failed, config, dry_run, started_at, completed_at, 
                        created_by, resumed_from, last_processed_id
                       FROM migration_jobs WHERE id = $1"#,
                )
                .bind(&new_job_id)
                .fetch_optional(pool)
                .await?;

                return Ok(new_job);
            }
        }

        Ok(None)
    }

    /// Cancel a job
    pub async fn cancel_job(&self, job_id: &str) -> anyhow::Result<bool> {
        // Only running or pending jobs can be cancelled
        if let Some(ref pool) = self.db {
            let result = sqlx::query(
                r#"UPDATE migration_jobs 
                   SET status = $1, completed_at = NOW()
                   WHERE id = $2 AND status IN ('pending', 'running', 'paused')"#,
            )
            .bind(MigrationStatus::Cancelled)
            .bind(job_id)
            .execute(pool)
            .await?;

            return Ok(result.rows_affected() > 0);
        }

        // Update Redis
        if let Some(ref redis) = self.redis {
            self.update_status(job_id, MigrationStatus::Cancelled).await?;
        }

        Ok(false)
    }

    /// Clean up old job data
    pub async fn cleanup_old_jobs(&self, days: i64) -> anyhow::Result<usize> {
        if let Some(ref pool) = self.db {
            let result = sqlx::query(
                r#"DELETE FROM migration_jobs 
                   WHERE completed_at < NOW() - INTERVAL '$1 days'
                   AND status IN ('completed', 'failed', 'cancelled')"#,
            )
            .bind(days)
            .execute(pool)
            .await?;

            return Ok(result.rows_affected() as usize);
        }

        Ok(0)
    }

    /// Publish progress update to pub/sub channel
    pub async fn publish_update(&self, job_id: &str) -> anyhow::Result<()> {
        if let Some(ref redis) = self.redis {
            let channel = format!("migration:updates:{}", job_id);
            let mut conn = redis.clone();

            redis::cmd("PUBLISH")
                .arg(&channel)
                .arg("update")
                .query_async::<_, ()>(&mut conn)
                .await?;
        }

        Ok(())
    }

    /// Subscribe to progress updates for a job
    pub async fn subscribe_to_updates(
        &self,
        job_id: &str,
    ) -> anyhow::Result<Option<tokio::sync::mpsc::Receiver<MigrationProgress>>> {
        if let Some(ref redis) = self.redis {
            let channel = format!("migration:updates:{}", job_id);
            let (tx, rx) = tokio::sync::mpsc::channel(100);

            let mut pubsub = redis.clone();
            // Note: In production, you'd use proper Redis pub/sub
            // This is a simplified version that polls

            let job_id = job_id.to_string();
            let tracker = ProgressTracker::new(Some(redis.clone()), self.db.clone());

            tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(1));

                loop {
                    interval.tick().await;

                    if let Ok(Some(progress)) = tracker.get_progress(&job_id).await {
                        if tx.send(progress).await.is_err() {
                            break;
                        }
                    } else {
                        break;
                    }
                }
            });

            return Ok(Some(rx));
        }

        Ok(None)
    }
}

/// Background job executor for migrations
pub struct MigrationBackgroundExecutor {
    tracker: ProgressTracker,
    sender: tokio::sync::mpsc::Sender<BackgroundJob>,
}

#[derive(Debug, Clone)]
struct BackgroundJob {
    job_id: String,
    tenant_id: String,
    source: MigrationSource,
}

impl MigrationBackgroundExecutor {
    /// Create a new background executor
    pub fn new(
        tracker: ProgressTracker,
        concurrency: usize,
    ) -> (Self, tokio::sync::mpsc::Receiver<BackgroundJob>) {
        let (sender, receiver) = tokio::sync::mpsc::channel(100);

        (Self { tracker, sender }, receiver)
    }

    /// Submit a job for background execution
    pub async fn submit(
        &self,
        job_id: String,
        tenant_id: String,
        source: MigrationSource,
    ) -> anyhow::Result<()> {
        let job = BackgroundJob {
            job_id,
            tenant_id,
            source,
        };

        self.sender.send(job).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_migration_progress_calculations() {
        let progress = MigrationProgress {
            id: "test".to_string(),
            source: "auth0".to_string(),
            status: MigrationStatus::Running,
            total_users: 100,
            processed: 50,
            succeeded: 45,
            failed: 5,
            percent_complete: 50.0,
            estimated_remaining_secs: None,
            current_operation: Some("Processing".to_string()),
            started_at: Utc::now(),
            completed_at: None,
            errors_count: 5,
        };

        assert_eq!(progress.percent_complete(), 50.0);
    }

    #[tokio::test]
    async fn test_progress_tracker_without_redis() {
        let tracker = ProgressTracker::new(None, None);

        // Should return None without panicking
        let progress = tracker.get_progress("test-id").await.unwrap();
        assert!(progress.is_none());
    }
}
