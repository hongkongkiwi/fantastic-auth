use crate::config::AuditLogRotationConfig;
use chrono::Utc;
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::time::{sleep, Duration};
use tracing::{info, warn};

pub fn spawn(config: AuditLogRotationConfig) {
    tokio::spawn(async move {
        let base_delay = Duration::from_secs(config.interval_minutes * 60);
        let max_backoff = base_delay.checked_mul(32).unwrap_or(base_delay);
        let mut delay = Duration::from_secs(0);
        let mut failures: u32 = 0;
        loop {
            sleep(delay).await;
            match rotate_if_needed(&config).await {
                Ok(_) => {
                    failures = 0;
                    delay = base_delay;
                }
                Err(err) => {
                    failures = failures.saturating_add(1);
                    crate::metrics_internal::record_audit_rotation_error();
                    let multiplier = 2u32.pow(failures.min(5));
                    delay = base_delay
                        .checked_mul(multiplier)
                        .unwrap_or(max_backoff)
                        .min(max_backoff);
                    warn!(
                        error = %err,
                        backoff_seconds = delay.as_secs(),
                        "Audit log rotation failed"
                    );
                }
            }
        }
    });
}

async fn rotate_if_needed(config: &AuditLogRotationConfig) -> anyhow::Result<()> {
    let path = PathBuf::from(&config.path);
    if !path.exists() {
        return Ok(());
    }

    let metadata = fs::metadata(&path).await?;
    let max_bytes = config.max_size_mb * 1024 * 1024;
    if metadata.len() < max_bytes {
        return Ok(());
    }

    let rotated = rotated_path(&path);
    fs::rename(&path, &rotated).await?;
    info!(
        path = %path.display(),
        rotated = %rotated.display(),
        "Rotated audit log"
    );
    crate::metrics_internal::record_audit_rotation();

    prune_old(&path, config.keep_files).await?;
    Ok(())
}

fn rotated_path(path: &Path) -> PathBuf {
    let timestamp = Utc::now().format("%Y%m%d%H%M%S");
    let file_name = match path.file_name().and_then(|s| s.to_str()) {
        Some(name) => name,
        None => "audit.log",
    };
    let rotated_name = format!("{}.{}", file_name, timestamp);
    path.with_file_name(rotated_name)
}

async fn prune_old(path: &Path, keep_files: usize) -> anyhow::Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("audit.log");

    let mut entries = fs::read_dir(dir).await?;
    let mut matches = Vec::new();
    while let Some(entry) = entries.next_entry().await? {
        let name = entry.file_name();
        if let Some(name) = name.to_str() {
            if name.starts_with(&format!("{}.", file_name)) {
                let metadata = entry.metadata().await?;
                matches.push((entry.path(), metadata.modified().ok()));
            }
        }
    }

    matches.sort_by_key(|(_, modified)| modified.clone());
    if matches.len() <= keep_files {
        return Ok(());
    }

    let remove_count = matches.len() - keep_files;
    for (path, _) in matches.into_iter().take(remove_count) {
        let _ = fs::remove_file(path).await;
    }

    Ok(())
}
