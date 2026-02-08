//! Analytics Background Jobs
//!
//! Handles aggregation of raw analytics events into time-series statistics:
//! - Hourly aggregation for real-time metrics
//! - Daily aggregation for dashboard data
//! - Weekly/Monthly rollup for trend analysis
//! - Cleanup of old raw events

use chrono::{DateTime, Datelike, Duration, TimeZone, Utc};
use sqlx::Row;
use std::sync::Arc;
use std::time::Duration as StdDuration;
use tokio::time::{interval, sleep};
use tracing::{debug, error, info, warn};

use crate::analytics::metrics::{AggregationConfig, AggregationJobType, AggregationStatus};
use crate::db::Database;

/// Analytics aggregation worker
pub struct AnalyticsAggregationWorker {
    db: Database,
    config: AggregationConfig,
}

impl AnalyticsAggregationWorker {
    /// Create a new aggregation worker
    pub fn new(db: Database, config: AggregationConfig) -> Self {
        Self { db, config }
    }

    /// Start the worker loop
    pub async fn start(self: Arc<Self>) {
        info!("Analytics aggregation worker started");

        // Run daily aggregation immediately on startup
        if let Err(e) = self.run_daily_aggregation().await {
            error!(error = %e, "Initial daily aggregation failed");
        }

        // Set up hourly ticker for hourly aggregation
        let mut hourly_ticker = interval(StdDuration::from_secs(3600));
        
        // Set up daily ticker for daily aggregation (run at 1 AM)
        let daily_interval = self.calculate_daily_interval().await;
        sleep(daily_interval).await;
        let mut daily_ticker = interval(StdDuration::from_secs(86400));

        // Set up weekly ticker (run on Mondays at 2 AM)
        let weekly_interval = self.calculate_weekly_interval().await;
        sleep(weekly_interval).await;
        let mut weekly_ticker = interval(StdDuration::from_secs(604800));

        // Set up cleanup ticker (run daily at 3 AM)
        let cleanup_interval = self.calculate_cleanup_interval().await;
        sleep(cleanup_interval).await;
        let mut cleanup_ticker = interval(StdDuration::from_secs(86400));

        loop {
            tokio::select! {
                _ = hourly_ticker.tick() => {
                    if self.config.hourly_enabled {
                        if let Err(e) = self.run_hourly_aggregation().await {
                            error!(error = %e, "Hourly aggregation failed");
                        }
                    }
                }
                _ = daily_ticker.tick() => {
                    if self.config.daily_enabled {
                        if let Err(e) = self.run_daily_aggregation().await {
                            error!(error = %e, "Daily aggregation failed");
                        }
                    }
                }
                _ = weekly_ticker.tick() => {
                    if self.config.weekly_enabled {
                        if let Err(e) = self.run_weekly_rollup().await {
                            error!(error = %e, "Weekly rollup failed");
                        }
                    }
                }
                _ = cleanup_ticker.tick() => {
                    if let Err(e) = self.run_cleanup().await {
                        error!(error = %e, "Analytics cleanup failed");
                    }
                }
            }
        }
    }

    /// Calculate sleep duration until next 1 AM
    async fn calculate_daily_interval(&self) -> StdDuration {
        let now = Utc::now();
        let next_run = now.date_naive().succ_opt().unwrap_or(now.date_naive())
            .and_hms_opt(1, 0, 0).unwrap()
            .and_local_timezone(Utc).unwrap();
        
        let duration = next_run - now;
        StdDuration::from_secs(duration.num_seconds().max(0) as u64)
    }

    /// Calculate sleep duration until next Monday 2 AM
    async fn calculate_weekly_interval(&self) -> StdDuration {
        let now = Utc::now();
        let days_until_monday = (8 - now.weekday().num_days_from_monday() as i64) % 7;
        
        let next_run = (now + Duration::days(days_until_monday))
            .date_naive()
            .and_hms_opt(2, 0, 0).unwrap()
            .and_local_timezone(Utc).unwrap();
        
        let duration = next_run - now;
        StdDuration::from_secs(duration.num_seconds().max(0) as u64)
    }

    /// Calculate sleep duration until next 3 AM
    async fn calculate_cleanup_interval(&self) -> StdDuration {
        let now = Utc::now();
        let next_run = now.date_naive().succ_opt().unwrap_or(now.date_naive())
            .and_hms_opt(3, 0, 0).unwrap()
            .and_local_timezone(Utc).unwrap();
        
        let duration = next_run - now;
        StdDuration::from_secs(duration.num_seconds().max(0) as u64)
    }

    /// Run hourly aggregation
    async fn run_hourly_aggregation(&self) -> anyhow::Result<()> {
        let job_id = self.create_job_record(AggregationJobType::Hourly).await?;
        let start_time = Utc::now();
        
        info!("Starting hourly analytics aggregation");

        let mut conn = self.db.acquire().await?;
        let mut tx = conn.begin().await?;

        // Aggregate last hour's events
        let hour = Utc::now() - Duration::hours(1);
        let hour_start = hour.with_minute(0).unwrap().with_second(0).unwrap().with_nanosecond(0).unwrap();
        let hour_end = hour_start + Duration::hours(1);

        // Get all tenant IDs
        let tenant_ids: Vec<String> = sqlx::query_scalar("SELECT id FROM tenants")
            .fetch_all(&mut *tx)
            .await?;

        let mut total_records = 0i64;

        for tenant_id in tenant_ids {
            // Aggregate logins
            let login_count: i64 = sqlx::query_scalar(
                r#"SELECT COUNT(*) FROM analytics_events 
                   WHERE tenant_id = $1 
                     AND event_type = 'login'
                     AND created_at >= $2 
                     AND created_at < $3"#,
            )
            .bind(&tenant_id)
            .bind(&hour_start)
            .bind(&hour_end)
            .fetch_one(&mut *tx)
            .await?;

            if login_count > 0 {
                sqlx::query(
                    r#"INSERT INTO analytics_hourly_stats 
                       (tenant_id, hour, metric_name, metric_value)
                       VALUES ($1, $2, 'login_total', $3)
                       ON CONFLICT (tenant_id, hour, metric_name)
                       DO UPDATE SET metric_value = EXCLUDED.metric_value"#,
                )
                .bind(&tenant_id)
                .bind(&hour_start)
                .bind(&login_count)
                .execute(&mut *tx)
                .await?;

                total_records += 1;
            }

            // Aggregate signups
            let signup_count: i64 = sqlx::query_scalar(
                r#"SELECT COUNT(*) FROM analytics_events 
                   WHERE tenant_id = $1 
                     AND event_type = 'signup'
                     AND created_at >= $2 
                     AND created_at < $3"#,
            )
            .bind(&tenant_id)
            .bind(&hour_start)
            .bind(&hour_end)
            .fetch_one(&mut *tx)
            .await?;

            if signup_count > 0 {
                sqlx::query(
                    r#"INSERT INTO analytics_hourly_stats 
                       (tenant_id, hour, metric_name, metric_value)
                       VALUES ($1, $2, 'signup_total', $3)
                       ON CONFLICT (tenant_id, hour, metric_name)
                       DO UPDATE SET metric_value = EXCLUDED.metric_value"#,
                )
                .bind(&tenant_id)
                .bind(&hour_start)
                .bind(&signup_count)
                .execute(&mut *tx)
                .await?;

                total_records += 1;
            }
        }

        tx.commit().await?;

        self.complete_job_record(&job_id, total_records, None).await?;

        info!(
            duration_ms = (Utc::now() - start_time).num_milliseconds(),
            records = total_records,
            "Hourly aggregation completed"
        );

        Ok(())
    }

    /// Run daily aggregation
    async fn run_daily_aggregation(&self) -> anyhow::Result<()> {
        let job_id = self.create_job_record(AggregationJobType::Daily).await?;
        let start_time = Utc::now();
        
        info!("Starting daily analytics aggregation");

        let mut conn = self.db.acquire().await?;

        // Aggregate yesterday's data
        let yesterday = Utc::now().date_naive() - chrono::Days::new(1);

        // Get all tenant IDs
        let tenant_ids: Vec<String> = sqlx::query_scalar("SELECT id FROM tenants")
            .fetch_all(&mut *conn)
            .await?;

        let mut total_records = 0i64;

        for tenant_id in tenant_ids {
            // Use the aggregate_daily_stats function
            let metrics = sqlx::query(
                "SELECT * FROM aggregate_daily_stats($1::date, $2::uuid)"
            )
            .bind(yesterday)
            .bind(&tenant_id)
            .fetch_all(&mut *conn)
            .await?;

            for row in metrics {
                let metric_name: String = row.try_get("metric_name")?;
                let metric_value: i64 = row.try_get("metric_value")?;

                sqlx::query(
                    "SELECT upsert_daily_stats($1, $2, $3, $4, '{}')"
                )
                .bind(&tenant_id)
                .bind(yesterday)
                .bind(&metric_name)
                .bind(metric_value)
                .execute(&mut *conn)
                .await?;

                total_records += 1;
            }

            // Aggregate login methods
            let method_stats = sqlx::query(
                r#"SELECT 
                    metadata->>'method' as method,
                    COUNT(*) as count
                   FROM analytics_events
                   WHERE tenant_id = $1 
                     AND event_type = 'login'
                     AND DATE(created_at) = $2
                   GROUP BY metadata->>'method'"#,
            )
            .bind(&tenant_id)
            .bind(yesterday)
            .fetch_all(&mut *conn)
            .await?;

            for row in method_stats {
                let method: Option<String> = row.try_get("method")?;
                let count: i64 = row.try_get("count")?;

                if let Some(method) = method {
                    let metric_name = format!("login_method_{}", method.to_lowercase());
                    
                    sqlx::query(
                        "SELECT upsert_daily_stats($1, $2, $3, $4, '{}')"
                    )
                    .bind(&tenant_id)
                    .bind(yesterday)
                    .bind(&metric_name)
                    .bind(count)
                    .execute(&mut *conn)
                    .await?;

                    total_records += 1;
                }
            }

            // Aggregate MFA methods
            let mfa_stats = sqlx::query(
                r#"SELECT 
                    metadata->>'method' as method,
                    COUNT(*) as count
                   FROM analytics_events
                   WHERE tenant_id = $1 
                     AND event_type = 'mfa'
                     AND DATE(created_at) = $2
                   GROUP BY metadata->>'method'"#,
            )
            .bind(&tenant_id)
            .bind(yesterday)
            .fetch_all(&mut *conn)
            .await?;

            for row in mfa_stats {
                let method: Option<String> = row.try_get("method")?;
                let count: i64 = row.try_get("count")?;

                if let Some(method) = method {
                    let metric_name = format!("mfa_method_{}", method.to_lowercase());
                    
                    sqlx::query(
                        "SELECT upsert_daily_stats($1, $2, $3, $4, '{}')"
                    )
                    .bind(&tenant_id)
                    .bind(yesterday)
                    .bind(&metric_name)
                    .bind(count)
                    .execute(&mut *conn)
                    .await?;

                    total_records += 1;
                }
            }
        }

        self.complete_job_record(&job_id, total_records, None).await?;

        info!(
            duration_ms = (Utc::now() - start_time).num_milliseconds(),
            records = total_records,
            "Daily aggregation completed"
        );

        Ok(())
    }

    /// Run weekly rollup
    async fn run_weekly_rollup(&self) -> anyhow::Result<()> {
        let job_id = self.create_job_record(AggregationJobType::Weekly).await?;
        let start_time = Utc::now();
        
        info!("Starting weekly analytics rollup");

        let mut conn = self.db.acquire().await?;

        // Calculate the week that just ended (previous Monday to Sunday)
        let today = Utc::now().date_naive();
        let days_since_monday = today.weekday().num_days_from_monday() as i64;
        let week_end = today - chrono::Days::new(days_since_monday as u64);
        let week_start = week_end - chrono::Days::new(7);

        // Get all tenant IDs
        let tenant_ids: Vec<String> = sqlx::query_scalar("SELECT id FROM tenants")
            .fetch_all(&mut *conn)
            .await?;

        let mut total_records = 0i64;

        for tenant_id in tenant_ids {
            // Roll up daily stats to weekly
            let metrics = sqlx::query(
                r#"SELECT 
                    metric_name,
                    SUM(metric_value) as total
                   FROM analytics_daily_stats
                   WHERE tenant_id = $1 
                     AND date >= $2 
                     AND date < $3
                   GROUP BY metric_name"#,
            )
            .bind(&tenant_id)
            .bind(week_start)
            .bind(week_end)
            .fetch_all(&mut *conn)
            .await?;

            for row in metrics {
                let metric_name: String = row.try_get("metric_name")?;
                let total: i64 = row.try_get("total")?;

                sqlx::query(
                    r#"INSERT INTO analytics_weekly_stats 
                       (tenant_id, week_start, metric_name, metric_value)
                       VALUES ($1, $2, $3, $4)
                       ON CONFLICT (tenant_id, week_start, metric_name)
                       DO UPDATE SET metric_value = EXCLUDED.metric_value"#,
                )
                .bind(&tenant_id)
                .bind(week_start)
                .bind(&metric_name)
                .bind(total)
                .execute(&mut *conn)
                .await?;

                total_records += 1;
            }
        }

        self.complete_job_record(&job_id, total_records, None).await?;

        info!(
            duration_ms = (Utc::now() - start_time).num_milliseconds(),
            records = total_records,
            "Weekly rollup completed"
        );

        Ok(())
    }

    /// Run monthly rollup
    async fn run_monthly_rollup(&self) -> anyhow::Result<()> {
        let job_id = self.create_job_record(AggregationJobType::Monthly).await?;
        let start_time = Utc::now();
        
        info!("Starting monthly analytics rollup");

        let mut conn = self.db.acquire().await?;

        // Calculate the month that just ended
        let today = Utc::now().date_naive();
        let month_start = if today.month() == 1 {
            chrono::NaiveDate::from_ymd_opt(today.year() - 1, 12, 1).unwrap()
        } else {
            chrono::NaiveDate::from_ymd_opt(today.year(), today.month() - 1, 1).unwrap()
        };

        // Get all tenant IDs
        let tenant_ids: Vec<String> = sqlx::query_scalar("SELECT id FROM tenants")
            .fetch_all(&mut *conn)
            .await?;

        let mut total_records = 0i64;

        for tenant_id in tenant_ids {
            // Roll up daily stats to monthly
            let metrics = sqlx::query(
                r#"SELECT 
                    metric_name,
                    SUM(metric_value) as total
                   FROM analytics_daily_stats
                   WHERE tenant_id = $1 
                     AND date >= $2 
                     AND date < DATE($2 + INTERVAL '1 month')
                   GROUP BY metric_name"#,
            )
            .bind(&tenant_id)
            .bind(month_start)
            .fetch_all(&mut *conn)
            .await?;

            for row in metrics {
                let metric_name: String = row.try_get("metric_name")?;
                let total: i64 = row.try_get("total")?;

                sqlx::query(
                    r#"INSERT INTO analytics_monthly_stats 
                       (tenant_id, month_start, metric_name, metric_value)
                       VALUES ($1, $2, $3, $4)
                       ON CONFLICT (tenant_id, month_start, metric_name)
                       DO UPDATE SET metric_value = EXCLUDED.metric_value"#,
                )
                .bind(&tenant_id)
                .bind(month_start)
                .bind(&metric_name)
                .bind(total)
                .execute(&mut *conn)
                .await?;

                total_records += 1;
            }
        }

        self.complete_job_record(&job_id, total_records, None).await?;

        info!(
            duration_ms = (Utc::now() - start_time).num_milliseconds(),
            records = total_records,
            "Monthly rollup completed"
        );

        Ok(())
    }

    /// Run cleanup of old analytics data
    async fn run_cleanup(&self) -> anyhow::Result<()> {
        let job_id = self.create_job_record(AggregationJobType::Cleanup).await?;
        let start_time = Utc::now();
        
        info!(
            raw_retention_days = self.config.raw_event_retention_days,
            "Starting analytics data cleanup"
        );

        let mut conn = self.db.acquire().await?;

        // Call the cleanup function
        let result = sqlx::query(
            "SELECT * FROM cleanup_old_analytics_data($1, $2)"
        )
        .bind(self.config.raw_event_retention_days)
        .bind(self.config.daily_stats_retention_days)
        .fetch_one(&mut *conn)
        .await?;

        let deleted_raw: i64 = result.try_get("deleted_raw_events")?;
        let deleted_hourly: i64 = result.try_get("deleted_hourly_stats")?;
        let deleted_snapshots: i64 = result.try_get("deleted_snapshots")?;

        let total_deleted = deleted_raw + deleted_hourly + deleted_snapshots;

        self.complete_job_record(&job_id, total_deleted, None).await?;

        info!(
            duration_ms = (Utc::now() - start_time).num_milliseconds(),
            deleted_raw_events = deleted_raw,
            deleted_hourly_stats = deleted_hourly,
            deleted_snapshots = deleted_snapshots,
            "Analytics cleanup completed"
        );

        Ok(())
    }

    /// Create a job record
    async fn create_job_record(&self, job_type: AggregationJobType) -> anyhow::Result<String> {
        let job_id = uuid::Uuid::new_v4().to_string();
        let job_type_str = format!("{:?}", job_type).to_lowercase();

        let mut conn = self.db.acquire().await?;

        sqlx::query(
            r#"INSERT INTO analytics_aggregation_jobs (id, job_type, status, started_at)
               VALUES ($1, $2, 'running', NOW())"#,
        )
        .bind(&job_id)
        .bind(&job_type_str)
        .execute(&mut *conn)
        .await?;

        Ok(job_id)
    }

    /// Complete a job record
    async fn complete_job_record(
        &self,
        job_id: &str,
        records_processed: i64,
        error: Option<String>,
    ) -> anyhow::Result<()> {
        let mut conn = self.db.acquire().await?;

        if let Some(err) = error {
            sqlx::query(
                r#"UPDATE analytics_aggregation_jobs 
                   SET status = 'failed', 
                       error_message = $1, 
                       completed_at = NOW()
                   WHERE id = $2"#,
            )
            .bind(&err)
            .bind(job_id)
            .execute(&mut *conn)
            .await?;
        } else {
            sqlx::query(
                r#"UPDATE analytics_aggregation_jobs 
                   SET status = 'completed', 
                       records_processed = $1, 
                       completed_at = NOW()
                   WHERE id = $2"#,
            )
            .bind(records_processed)
            .bind(job_id)
            .execute(&mut *conn)
            .await?;
        }

        Ok(())
    }

    /// Get aggregation job status
    pub async fn get_job_status(&self, job_type: AggregationJobType) -> anyhow::Result<Option<AggregationStatus>> {
        let job_type_str = format!("{:?}", job_type).to_lowercase();
        
        let mut conn = self.db.acquire().await?;

        let row = sqlx::query(
            r#"SELECT 
                job_type,
                completed_at as last_run,
                status,
                records_processed,
                error_message
               FROM analytics_aggregation_jobs
               WHERE job_type = $1
               ORDER BY completed_at DESC
               LIMIT 1"#,
        )
        .bind(&job_type_str)
        .fetch_optional(&mut *conn)
        .await?;

        if let Some(row) = row {
            Ok(Some(AggregationStatus {
                job_type,
                last_run: row.try_get("last_run")?,
                last_success: if row.try_get::<Option<String>, _>("status")?.as_deref() == Some("completed") {
                    row.try_get("last_run")?
                } else {
                    None
                },
                last_error: row.try_get("error_message")?,
                records_processed: row.try_get("records_processed")?,
            }))
        } else {
            Ok(None)
        }
    }
}

/// Spawn the analytics aggregation worker
pub fn spawn_worker(db: Database, config: AggregationConfig) -> Arc<AnalyticsAggregationWorker> {
    let worker = Arc::new(AnalyticsAggregationWorker::new(db, config));
    let worker_clone = worker.clone();

    tokio::spawn(async move {
        worker_clone.start().await;
    });

    worker
}

/// Manually trigger daily aggregation (for testing/admin use)
pub async fn trigger_daily_aggregation(db: &Database) -> anyhow::Result<i64> {
    let config = AggregationConfig::default();
    let worker = AnalyticsAggregationWorker::new(db.clone(), config);
    worker.run_daily_aggregation().await?;
    
    // Get last job record
    let mut conn = db.acquire().await?;
    let count: i64 = sqlx::query_scalar(
        r#"SELECT records_processed 
           FROM analytics_aggregation_jobs 
           WHERE job_type = 'daily'
           ORDER BY created_at DESC 
           LIMIT 1"#,
    )
    .fetch_one(&mut *conn)
    .await?;

    Ok(count)
}

/// Get aggregation statistics
pub async fn get_aggregation_stats(db: &Database) -> anyhow::Result<serde_json::Value> {
    let mut conn = db.acquire().await?;

    // Get counts of aggregated data
    let daily_stats_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM analytics_daily_stats"
    )
    .fetch_one(&mut *conn)
    .await?;

    let hourly_stats_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM analytics_hourly_stats"
    )
    .fetch_one(&mut *conn)
    .await?;

    let weekly_stats_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM analytics_weekly_stats"
    )
    .fetch_one(&mut *conn)
    .await?;

    let events_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM analytics_events"
    )
    .fetch_one(&mut *conn)
    .await?;

    // Get recent job status
    let recent_jobs: Vec<serde_json::Value> = sqlx::query_as::<_, (String, String, Option<chrono::DateTime<Utc>>, i64)>(
        r#"SELECT job_type, status, completed_at, records_processed
           FROM analytics_aggregation_jobs
           ORDER BY created_at DESC
           LIMIT 10"#,
    )
    .fetch_all(&mut *conn)
    .await?
    .into_iter()
    .map(|(job_type, status, completed_at, records)| {
        serde_json::json!({
            "job_type": job_type,
            "status": status,
            "completed_at": completed_at,
            "records_processed": records,
        })
    })
    .collect();

    Ok(serde_json::json!({
        "aggregated_data": {
            "daily_stats": daily_stats_count,
            "hourly_stats": hourly_stats_count,
            "weekly_stats": weekly_stats_count,
            "raw_events": events_count,
        },
        "recent_jobs": recent_jobs,
    }))
}
