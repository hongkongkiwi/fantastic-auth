use std::time::Duration;

use chrono::{Duration as ChronoDuration, Utc};
use tracing::info;

use crate::state::AppState;

pub fn spawn(state: AppState, interval: Duration) {
    tokio::spawn(async move {
        loop {
            if let Err(e) = run_once(&state).await {
                tracing::error!(error = %e, "Audit retention cleanup failed");
            }
            tokio::time::sleep(interval).await;
        }
    });
}

async fn run_once(state: &AppState) -> anyhow::Result<()> {
    let tenants = state
        .settings_service
        .list_privacy_retention()
        .await
        .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    let mut total_deleted = 0u64;

    for (tenant_id, retention_days) in tenants {
        let retention_days = retention_days.max(1);
        let cutoff = Utc::now() - ChronoDuration::days(retention_days as i64);
        let deleted = state
            .db
            .audit()
            .prune_older_than(&tenant_id, cutoff)
            .await?;
        total_deleted += deleted;
    }

    info!(deleted = total_deleted, "Audit retention cleanup complete");
    Ok(())
}
