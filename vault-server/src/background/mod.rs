use std::time::Duration;

use crate::config::Config;
use crate::db::Database;
use crate::state::AppState;
use tracing::info;

mod analytics;
mod audit_prune;
mod audit_rotation;
mod log_streams;
pub mod webhook_worker;
pub mod webhooks;

pub use analytics::{spawn_worker as spawn_analytics_worker, trigger_daily_aggregation};

/// Start all background workers
pub fn start(config: &Config, _db: &Database, state: &AppState) {
    if let Some(ref rotation) = config.background_jobs.audit_log_rotation {
        audit_rotation::spawn(rotation.clone());
        info!(path = rotation.path.as_str(), "Audit log rotation enabled");
    }
    if let Some(ref prune) = config.background_jobs.audit_log_prune {
        audit_prune::spawn(prune.clone());
        info!(path = prune.path.as_str(), "Audit log prune enabled");
    }

    // Start analytics aggregation worker
    spawn_analytics_worker(
        state.db.clone(),
        crate::analytics::models::AggregationConfig::default(),
    );
    info!("Analytics aggregation worker started");

    // Start webhook worker if enabled
    if config.webhook.enabled {
        webhook_worker::spawn_worker_with_config(
            state.db.clone(),
            state.webhook_service.clone(),
            Duration::from_secs(config.webhook.worker_poll_interval_seconds),
            config.webhook.batch_size as i64,
        );
        info!(
            poll_interval_secs = config.webhook.worker_poll_interval_seconds,
            batch_size = config.webhook.batch_size,
            "Webhook worker started"
        );
    } else {
        info!("Webhook worker disabled");
    }

    // Start log streaming worker
    log_streams::start(state.clone());
    info!("Log streaming worker started");
}
