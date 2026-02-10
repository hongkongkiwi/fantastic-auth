//! Monitoring and health check system
//!
//! Provides health checks, readiness/liveness probes, and metrics collection.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;

mod metrics;

pub use metrics::*;

/// Health check status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

impl std::fmt::Display for HealthStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HealthStatus::Healthy => write!(f, "healthy"),
            HealthStatus::Degraded => write!(f, "degraded"),
            HealthStatus::Unhealthy => write!(f, "unhealthy"),
        }
    }
}

/// Component health check result
#[derive(Debug, Clone, Serialize)]
pub struct ComponentHealth {
    pub name: String,
    pub status: HealthStatus,
    pub response_time_ms: u64,
    pub message: Option<String>,
    pub last_checked: chrono::DateTime<chrono::Utc>,
}

/// Overall system health
#[derive(Debug, Clone, Serialize)]
pub struct SystemHealth {
    pub status: HealthStatus,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub version: String,
    pub uptime_seconds: u64,
    pub components: Vec<ComponentHealth>,
}

/// Health check registry
#[derive(Clone)]
pub struct HealthRegistry {
    components: Arc<RwLock<HashMap<String, ComponentHealth>>>,
    start_time: Instant,
}

impl HealthRegistry {
    pub fn new() -> Self {
        Self {
            components: Arc::new(RwLock::new(HashMap::new())),
            start_time: Instant::now(),
        }
    }

    /// Register a component health check
    pub async fn register(&self, name: &str, check: ComponentHealth) {
        let mut components = self.components.write().await;
        components.insert(name.to_string(), check);
    }

    /// Get overall system health
    pub async fn check_health(&self) -> SystemHealth {
        let components = self.components.read().await;

        let component_list: Vec<ComponentHealth> = components.values().cloned().collect();

        // Determine overall status
        let status = if component_list
            .iter()
            .any(|c| matches!(c.status, HealthStatus::Unhealthy))
        {
            HealthStatus::Unhealthy
        } else if component_list
            .iter()
            .any(|c| matches!(c.status, HealthStatus::Degraded))
        {
            HealthStatus::Degraded
        } else {
            HealthStatus::Healthy
        };

        SystemHealth {
            status,
            timestamp: chrono::Utc::now(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            uptime_seconds: self.start_time.elapsed().as_secs(),
            components: component_list,
        }
    }

    /// Get specific component health
    pub async fn get_component(&self, name: &str) -> Option<ComponentHealth> {
        let components = self.components.read().await;
        components.get(name).cloned()
    }

    /// Run all health checks and update registry
    pub async fn run_checks(
        &self,
        db: &crate::db::Database,
        redis: &Option<redis::aio::ConnectionManager>,
    ) {
        // Check database
        let db_health = self.check_database(db).await;
        self.register("database", db_health).await;

        // Check Redis (if configured)
        if let Some(redis) = redis {
            let redis_health = self.check_redis(redis).await;
            self.register("redis", redis_health).await;
        }
    }

    async fn check_database(&self, db: &crate::db::Database) -> ComponentHealth {
        let start = Instant::now();

        match sqlx::query("SELECT 1").fetch_one(db.pool()).await {
            Ok(_) => ComponentHealth {
                name: "database".to_string(),
                status: HealthStatus::Healthy,
                response_time_ms: start.elapsed().as_millis() as u64,
                message: None,
                last_checked: chrono::Utc::now(),
            },
            Err(e) => ComponentHealth {
                name: "database".to_string(),
                status: HealthStatus::Unhealthy,
                response_time_ms: start.elapsed().as_millis() as u64,
                message: Some(format!("Database error: {}", e)),
                last_checked: chrono::Utc::now(),
            },
        }
    }

    async fn check_redis(&self, redis: &redis::aio::ConnectionManager) -> ComponentHealth {
        let start = Instant::now();

        let mut conn = redis.clone();
        match redis::cmd("PING").query_async::<_, String>(&mut conn).await {
            Ok(_) => ComponentHealth {
                name: "redis".to_string(),
                status: HealthStatus::Healthy,
                response_time_ms: start.elapsed().as_millis() as u64,
                message: None,
                last_checked: chrono::Utc::now(),
            },
            Err(e) => ComponentHealth {
                name: "redis".to_string(),
                status: HealthStatus::Unhealthy,
                response_time_ms: start.elapsed().as_millis() as u64,
                message: Some(format!("Redis error: {}", e)),
                last_checked: chrono::Utc::now(),
            },
        }
    }
}

impl Default for HealthRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Request metrics tracking
#[derive(Clone)]
pub struct RequestMetrics {
    total_requests: Arc<RwLock<u64>>,
    error_count: Arc<RwLock<u64>>,
    request_duration_ms: Arc<RwLock<Vec<u64>>>,
}

impl RequestMetrics {
    pub fn new() -> Self {
        Self {
            total_requests: Arc::new(RwLock::new(0)),
            error_count: Arc::new(RwLock::new(0)),
            request_duration_ms: Arc::new(RwLock::new(Vec::with_capacity(1000))),
        }
    }

    pub async fn record_request(&self, duration_ms: u64, is_error: bool) {
        let mut total = self.total_requests.write().await;
        *total += 1;

        if is_error {
            let mut errors = self.error_count.write().await;
            *errors += 1;
        }

        let mut durations = self.request_duration_ms.write().await;
        durations.push(duration_ms);
        // Keep only last 1000 measurements
        if durations.len() > 1000 {
            durations.remove(0);
        }
    }

    pub async fn get_stats(&self) -> MetricsStats {
        let total = *self.total_requests.read().await;
        let errors = *self.error_count.read().await;
        let durations = self.request_duration_ms.read().await;

        let avg_duration = if !durations.is_empty() {
            durations.iter().sum::<u64>() / durations.len() as u64
        } else {
            0
        };

        let p95 = if !durations.is_empty() {
            let mut sorted = durations.clone();
            sorted.sort_unstable();
            let idx = (sorted.len() as f64 * 0.95) as usize;
            sorted.get(idx).copied().unwrap_or(0)
        } else {
            0
        };

        MetricsStats {
            total_requests: total,
            error_count: errors,
            error_rate: if total > 0 {
                errors as f64 / total as f64
            } else {
                0.0
            },
            avg_response_time_ms: avg_duration,
            p95_response_time_ms: p95,
        }
    }
}

impl Default for RequestMetrics {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct MetricsStats {
    pub total_requests: u64,
    pub error_count: u64,
    pub error_rate: f64,
    pub avg_response_time_ms: u64,
    pub p95_response_time_ms: u64,
}
