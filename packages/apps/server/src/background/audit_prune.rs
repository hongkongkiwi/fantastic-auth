use crate::config::AuditLogPruneConfig;
use chrono::{Duration as ChronoDuration, Utc};
use std::path::PathBuf;
use tokio::fs;
use tokio::time::{sleep, Duration};
use tracing::{info, warn};

pub fn spawn(config: AuditLogPruneConfig) {
    tokio::spawn(async move {
        let base_delay = Duration::from_secs(config.interval_minutes * 60);
        let max_backoff = base_delay.checked_mul(32).unwrap_or(base_delay);
        let mut delay = Duration::from_secs(0);
        let mut failures: u32 = 0;
        loop {
            sleep(delay).await;
            match prune_if_needed(&config).await {
                Ok(_) => {
                    failures = 0;
                    delay = base_delay;
                }
                Err(err) => {
                    failures = failures.saturating_add(1);
                    crate::metrics_internal::record_audit_prune_error();
                    let multiplier = 2u32.pow(failures.min(5));
                    delay = base_delay
                        .checked_mul(multiplier)
                        .unwrap_or(max_backoff)
                        .min(max_backoff);
                    warn!(
                        error = %err,
                        backoff_seconds = delay.as_secs(),
                        "Audit log prune failed"
                    );
                }
            }
        }
    });
}

/// Maximum audit log file size (100MB)
const MAX_AUDIT_LOG_SIZE: u64 = 100 * 1024 * 1024;

async fn prune_if_needed(config: &AuditLogPruneConfig) -> anyhow::Result<()> {
    let path = PathBuf::from(&config.path);
    if !path.exists() {
        return Ok(());
    }

    // SECURITY: Check file size before reading to prevent OOM
    let metadata = fs::metadata(&path).await?;
    if metadata.len() > MAX_AUDIT_LOG_SIZE {
        warn!(
            path = %path.display(),
            size = metadata.len(),
            max_size = MAX_AUDIT_LOG_SIZE,
            "Audit log file too large, truncating"
        );
        // Truncate the file to prevent OOM
        fs::write(&path, "[]").await?;
        return Ok(());
    }

    let content = fs::read_to_string(&path).await?;
    if content.is_empty() {
        return Ok(());
    }

    let cutoff = Utc::now() - ChronoDuration::days(config.retention_days as i64);
    let mut kept = Vec::new();

    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<serde_json::Value>(line) {
            Ok(value) => {
                let ts = value.get("timestamp").and_then(|v| v.as_str());
                if let Some(ts) = ts {
                    if let Ok(parsed) = ts.parse::<chrono::DateTime<Utc>>() {
                        if parsed >= cutoff {
                            kept.push(line);
                        }
                    }
                }
            }
            Err(_) => {
                // Ignore malformed lines
            }
        }
    }

    let new_content = kept.join("\n");
    fs::write(&path, new_content).await?;
    info!(path = %path.display(), kept = kept.len(), "Pruned audit log lines");
    crate::metrics_internal::record_audit_prune();
    Ok(())
}
