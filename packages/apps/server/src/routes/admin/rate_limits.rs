//! Admin Rate Limiting Dashboard Routes
//!
//! Provides endpoints for viewing and managing rate limits:
//! - GET /api/v1/admin/rate-limits - Get current rate limit configuration
//! - PUT /api/v1/admin/rate-limits/config - Update rate limit configuration
//! - GET /api/v1/admin/rate-limits/violations - Get rate limit violations
//! - GET /api/v1/admin/rate-limits/blocked-ips - Get blocked IPs
//! - POST /api/v1/admin/rate-limits/block-ip - Block an IP
//! - DELETE /api/v1/admin/rate-limits/block-ip/:ip - Unblock an IP
//! - GET /api/v1/admin/rate-limits/metrics - Get rate limiting metrics

use axum::{
    extract::{Extension, Path, Query, State},
    routing::{delete, get, post, put},
    Extension as _, Json, Router,
};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::audit::{AuditAction, AuditLogger, ResourceType};
use crate::routes::ApiError;
use crate::state::{AppState, CurrentUser};

/// Rate limiting routes
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/rate-limits", get(get_rate_limits))
        .route("/rate-limits/config", put(update_rate_limit_config))
        .route("/rate-limits/violations", get(get_violations))
        .route("/rate-limits/blocked-ips", get(get_blocked_ips))
        .route("/rate-limits/block-ip", post(block_ip))
        .route("/rate-limits/block-ip/:ip", delete(unblock_ip))
        .route("/rate-limits/metrics", get(get_metrics))
}

// ============ Request/Response Types ============

/// Rate limit configuration
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RateLimitConfig {
    /// General API rate limit (requests per minute)
    pub api_per_minute: u32,
    /// Authentication endpoint rate limit (requests per minute)
    pub auth_per_minute: u32,
    /// Window size in seconds
    pub window_seconds: u64,
    /// Burst allowance
    pub burst_allowance: u32,
    /// Per-user rate limit multiplier
    pub user_multiplier: f64,
    /// Per-IP rate limit multiplier  
    pub ip_multiplier: f64,
    /// Whether to block IPs after repeated violations
    pub auto_block_enabled: bool,
    /// Number of violations before auto-block
    pub auto_block_threshold: u32,
    /// Auto-block duration in minutes
    pub auto_block_duration_minutes: i64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            api_per_minute: 100,
            auth_per_minute: 10,
            window_seconds: 60,
            burst_allowance: 10,
            user_multiplier: 2.0,
            ip_multiplier: 1.0,
            auto_block_enabled: true,
            auto_block_threshold: 10,
            auto_block_duration_minutes: 60,
        }
    }
}

/// Rate limits response
#[derive(Debug, Serialize)]
pub struct RateLimitsResponse {
    /// Current configuration
    pub config: RateLimitConfig,
    /// Effective limits for different endpoints
    pub effective_limits: HashMap<String, EndpointLimit>,
    /// Current status
    pub status: RateLimitStatus,
}

#[derive(Debug, Serialize)]
pub struct EndpointLimit {
    pub endpoint: String,
    pub requests_per_minute: u32,
    pub burst: u32,
    pub description: String,
}

#[derive(Debug, Serialize)]
pub struct RateLimitStatus {
    pub total_violations_24h: i64,
    pub active_blocked_ips: i64,
    pub average_requests_per_minute: f64,
    pub peak_requests_per_minute: i64,
}

/// Update rate limit config request
#[derive(Debug, Deserialize)]
pub struct UpdateRateLimitConfigRequest {
    pub api_per_minute: Option<u32>,
    pub auth_per_minute: Option<u32>,
    pub window_seconds: Option<u64>,
    pub burst_allowance: Option<u32>,
    pub auto_block_enabled: Option<bool>,
    pub auto_block_threshold: Option<u32>,
    pub auto_block_duration_minutes: Option<i64>,
}

/// Rate limit violation
#[derive(Debug, Serialize)]
pub struct RateLimitViolation {
    pub id: String,
    pub timestamp: String,
    pub ip_address: String,
    pub user_id: Option<String>,
    pub endpoint: String,
    pub limit_type: String,
    pub requests_made: u32,
    pub limit: u32,
}

/// List violations query
#[derive(Debug, Deserialize)]
pub struct ListViolationsQuery {
    pub start: Option<DateTime<Utc>>,
    pub end: Option<DateTime<Utc>>,
    pub ip: Option<String>,
    pub limit: Option<i64>,
}

/// Blocked IP entry
#[derive(Debug, Serialize)]
pub struct BlockedIpEntry {
    pub ip_address: String,
    pub blocked_at: String,
    pub blocked_until: Option<String>,
    pub blocked_by: String,
    pub reason: String,
    pub violation_count: i64,
}

/// Block IP request
#[derive(Debug, Deserialize)]
pub struct BlockIpRequest {
    pub ip_address: String,
    pub duration_minutes: Option<i64>,
    pub reason: String,
}

/// Rate limiting metrics
#[derive(Debug, Serialize)]
pub struct RateLimitMetrics {
    pub period: MetricsPeriod,
    pub requests: RequestMetrics,
    pub violations: ViolationMetrics,
    pub top_blocked_ips: Vec<TopBlockedIp>,
    pub hourly_distribution: Vec<HourlyStat>,
}

#[derive(Debug, Serialize)]
pub struct MetricsPeriod {
    pub start: String,
    pub end: String,
    pub hours: i64,
}

#[derive(Debug, Serialize)]
pub struct RequestMetrics {
    pub total: i64,
    pub allowed: i64,
    pub blocked: i64,
    pub average_latency_ms: f64,
}

#[derive(Debug, Serialize)]
pub struct ViolationMetrics {
    pub total: i64,
    pub by_endpoint: HashMap<String, i64>,
    pub by_ip: HashMap<String, i64>,
    pub repeat_offenders: Vec<RepeatOffender>,
}

#[derive(Debug, Serialize)]
pub struct RepeatOffender {
    pub ip_address: String,
    pub violation_count: i64,
    pub first_violation: String,
    pub last_violation: String,
}

#[derive(Debug, Serialize)]
pub struct TopBlockedIp {
    pub ip_address: String,
    pub block_count: i64,
    pub last_blocked: String,
}

#[derive(Debug, Serialize)]
pub struct HourlyStat {
    pub hour: String,
    pub requests: i64,
    pub violations: i64,
    pub blocked: i64,
}

// ============ Handlers ============

/// Get current rate limit configuration and status
async fn get_rate_limits(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<RateLimitsResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    // Get config from tenant settings or use default
    let config = get_tenant_rate_limit_config(&state, &current_user.tenant_id).await?;

    // Build effective limits map
    let mut effective_limits = HashMap::new();
    effective_limits.insert(
        "api".to_string(),
        EndpointLimit {
            endpoint: "/api/v1/*".to_string(),
            requests_per_minute: config.api_per_minute,
            burst: config.burst_allowance,
            description: "General API endpoints".to_string(),
        },
    );
    effective_limits.insert(
        "auth".to_string(),
        EndpointLimit {
            endpoint: "/api/v1/auth/*".to_string(),
            requests_per_minute: config.auth_per_minute,
            burst: config.burst_allowance / 2,
            description: "Authentication endpoints".to_string(),
        },
    );
    effective_limits.insert(
        "admin".to_string(),
        EndpointLimit {
            endpoint: "/api/v1/admin/*".to_string(),
            requests_per_minute: config.api_per_minute * 2,
            burst: config.burst_allowance * 2,
            description: "Admin endpoints (higher limit)".to_string(),
        },
    );

    // Get current status
    let violations_24h: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM rate_limit_violations 
         WHERE tenant_id = $1 AND timestamp > NOW() - INTERVAL '24 hours'",
    )
    .bind(&current_user.tenant_id)
    .fetch_one(state.db.pool())
    .await
    .unwrap_or(0);

    let blocked_ips: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM blocked_ips 
         WHERE tenant_id = $1 AND (blocked_until IS NULL OR blocked_until > NOW())",
    )
    .bind(&current_user.tenant_id)
    .fetch_one(state.db.pool())
    .await
    .unwrap_or(0);

    Ok(Json(RateLimitsResponse {
        config,
        effective_limits,
        status: RateLimitStatus {
            total_violations_24h: violations_24h,
            active_blocked_ips: blocked_ips,
            average_requests_per_minute: 0.0, // Would calculate from metrics
            peak_requests_per_minute: 0,
        },
    }))
}

/// Update rate limit configuration
async fn update_rate_limit_config(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<UpdateRateLimitConfigRequest>,
) -> Result<Json<RateLimitConfig>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    // Get current config
    let mut config = get_tenant_rate_limit_config(&state, &current_user.tenant_id).await?;

    // Apply updates
    if let Some(api_per_minute) = req.api_per_minute {
        config.api_per_minute = api_per_minute;
    }
    if let Some(auth_per_minute) = req.auth_per_minute {
        config.auth_per_minute = auth_per_minute;
    }
    if let Some(window_seconds) = req.window_seconds {
        config.window_seconds = window_seconds;
    }
    if let Some(burst) = req.burst_allowance {
        config.burst_allowance = burst;
    }
    if let Some(auto_block) = req.auto_block_enabled {
        config.auto_block_enabled = auto_block;
    }
    if let Some(threshold) = req.auto_block_threshold {
        config.auto_block_threshold = threshold;
    }
    if let Some(duration) = req.auto_block_duration_minutes {
        config.auto_block_duration_minutes = duration;
    }

    sqlx::query(
        r#"INSERT INTO tenant_rate_limit_configs
           (tenant_id, api_per_minute, auth_per_minute, window_seconds, burst_allowance,
            auto_block_enabled, auto_block_threshold, auto_block_duration_minutes, updated_at, updated_by)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), $9)
           ON CONFLICT (tenant_id)
           DO UPDATE SET api_per_minute = $2, auth_per_minute = $3, window_seconds = $4,
                         burst_allowance = $5, auto_block_enabled = $6, auto_block_threshold = $7,
                         auto_block_duration_minutes = $8, updated_at = NOW(), updated_by = $9"#,
    )
    .bind(&current_user.tenant_id)
    .bind(config.api_per_minute as i32)
    .bind(config.auth_per_minute as i32)
    .bind(config.window_seconds as i32)
    .bind(config.burst_allowance as i32)
    .bind(config.auto_block_enabled)
    .bind(config.auto_block_threshold as i32)
    .bind(config.auto_block_duration_minutes as i32)
    .bind(&current_user.user_id)
    .execute(state.db.pool())
    .await
    .map_err(|_| ApiError::internal())?;

    // Log the change
    let audit = AuditLogger::new(state.db.clone());
    audit.log(
        &current_user.tenant_id,
        AuditAction::Custom("rate_limits.config_updated"),
        ResourceType::Admin,
        &current_user.tenant_id,
        Some(current_user.user_id.clone()),
        None,
        None,
        true,
        None,
        Some(serde_json::json!({
            "api_per_minute": config.api_per_minute,
            "auth_per_minute": config.auth_per_minute,
            "auto_block_enabled": config.auto_block_enabled,
        })),
    );

    Ok(Json(config))
}

/// Get rate limit violations
async fn get_violations(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Query(query): Query<ListViolationsQuery>,
) -> Result<Json<Vec<RateLimitViolation>>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    let start = query
        .start
        .unwrap_or_else(|| Utc::now() - Duration::hours(24));
    let end = query.end.unwrap_or_else(Utc::now);
    let limit = query.limit.unwrap_or(100).clamp(1, 1000);

    let rows = if let Some(ref ip) = query.ip {
        sqlx::query_as::<_, (String, DateTime<Utc>, String, Option<String>, String, String, i32, i32)>(
            r#"SELECT id::text, timestamp, ip_address, user_id::text, endpoint, limit_type, 
                      requests_made, limit_value
               FROM rate_limit_violations
               WHERE tenant_id = $1 AND timestamp >= $2 AND timestamp <= $3
                 AND ip_address = $4
               ORDER BY timestamp DESC
               LIMIT $5"#,
        )
        .bind(&current_user.tenant_id)
        .bind(start)
        .bind(end)
        .bind(ip)
        .bind(limit)
        .fetch_all(state.db.pool())
        .await
    } else {
        sqlx::query_as::<_, (String, DateTime<Utc>, String, Option<String>, String, String, i32, i32)>(
            r#"SELECT id::text, timestamp, ip_address, user_id::text, endpoint, limit_type, 
                      requests_made, limit_value
               FROM rate_limit_violations
               WHERE tenant_id = $1 AND timestamp >= $2 AND timestamp <= $3
               ORDER BY timestamp DESC
               LIMIT $4"#,
        )
        .bind(&current_user.tenant_id)
        .bind(start)
        .bind(end)
        .bind(limit)
        .fetch_all(state.db.pool())
        .await
    }
    .map_err(|_| ApiError::internal())?;

    let violations: Vec<RateLimitViolation> = rows
        .into_iter()
        .map(|(id, timestamp, ip, user, endpoint, limit_type, requests, limit)| {
            RateLimitViolation {
                id,
                timestamp: timestamp.to_rfc3339(),
                ip_address: ip,
                user_id: user,
                endpoint,
                limit_type,
                requests_made: requests as u32,
                limit: limit as u32,
            }
        })
        .collect();

    Ok(Json(violations))
}

/// Get blocked IPs
async fn get_blocked_ips(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<Vec<BlockedIpEntry>>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    let rows = sqlx::query_as::<_, (String, DateTime<Utc>, Option<DateTime<Utc>>, String, String, i64)>(
        r#"SELECT ip_address, blocked_at, blocked_until, blocked_by, reason, violation_count
           FROM blocked_ips
           WHERE tenant_id = $1 AND (blocked_until IS NULL OR blocked_until > NOW())
           ORDER BY blocked_at DESC"#,
    )
    .bind(&current_user.tenant_id)
    .fetch_all(state.db.pool())
    .await
    .map_err(|_| ApiError::internal())?;

    let entries: Vec<BlockedIpEntry> = rows
        .into_iter()
        .map(|(ip, blocked_at, blocked_until, blocked_by, reason, count)| BlockedIpEntry {
            ip_address: ip,
            blocked_at: blocked_at.to_rfc3339(),
            blocked_until: blocked_until.map(|dt| dt.to_rfc3339()),
            blocked_by,
            reason,
            violation_count: count,
        })
        .collect();

    Ok(Json(entries))
}

/// Block an IP address
async fn block_ip(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<BlockIpRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    let blocked_at = Utc::now();
    let blocked_until = req
        .duration_minutes
        .map(|mins| blocked_at + Duration::minutes(mins));

    sqlx::query(
        r#"INSERT INTO blocked_ips 
           (tenant_id, ip_address, blocked_at, blocked_until, blocked_by, reason, violation_count)
           VALUES ($1, $2, $3, $4, $5, $6, 0)
           ON CONFLICT (tenant_id, ip_address) 
           DO UPDATE SET blocked_at = $3, blocked_until = $4, blocked_by = $5, reason = $6"#,
    )
    .bind(&current_user.tenant_id)
    .bind(&req.ip_address)
    .bind(blocked_at)
    .bind(blocked_until)
    .bind(&current_user.user_id)
    .bind(&req.reason)
    .execute(state.db.pool())
    .await
    .map_err(|_| ApiError::internal())?;

    // Log the action
    let audit = AuditLogger::new(state.db.clone());
    audit.log(
        &current_user.tenant_id,
        AuditAction::Custom("ip.blocked"),
        ResourceType::Admin,
        &req.ip_address,
        Some(current_user.user_id.clone()),
        None,
        None,
        true,
        Some(format!("Blocked IP: {}", req.ip_address)),
        Some(serde_json::json!({
            "ip_address": req.ip_address,
            "duration_minutes": req.duration_minutes,
            "reason": req.reason,
        })),
    );

    Ok(Json(serde_json::json!({
        "message": "IP blocked successfully",
        "ip_address": req.ip_address,
        "blocked_until": blocked_until.map(|dt| dt.to_rfc3339()),
    })))
}

/// Unblock an IP address
async fn unblock_ip(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(ip): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    let result = sqlx::query(
        "DELETE FROM blocked_ips WHERE tenant_id = $1 AND ip_address = $2",
    )
    .bind(&current_user.tenant_id)
    .bind(&ip)
    .execute(state.db.pool())
    .await
    .map_err(|_| ApiError::internal())?;

    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }

    // Log the action
    let audit = AuditLogger::new(state.db.clone());
    audit.log(
        &current_user.tenant_id,
        AuditAction::Custom("ip.unblocked"),
        ResourceType::Admin,
        &ip,
        Some(current_user.user_id.clone()),
        None,
        None,
        true,
        Some(format!("Unblocked IP: {}", ip)),
        None,
    );

    Ok(Json(serde_json::json!({
        "message": "IP unblocked successfully",
        "ip_address": ip,
    })))
}

/// Get rate limiting metrics
async fn get_metrics(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<RateLimitMetrics>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    let end = Utc::now();
    let start = end - Duration::hours(24);

    // Total requests (would come from metrics/audit logs)
    let total_requests: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_logs 
         WHERE tenant_id = $1 AND created_at >= $2 AND created_at <= $3",
    )
    .bind(&current_user.tenant_id)
    .bind(start)
    .bind(end)
    .fetch_one(state.db.pool())
    .await
    .unwrap_or(0);

    // Violations
    let violations: Vec<(String, i64)> = sqlx::query_as(
        r#"SELECT endpoint, COUNT(*) as count
           FROM rate_limit_violations
           WHERE tenant_id = $1 AND timestamp >= $2 AND timestamp <= $3
           GROUP BY endpoint
           ORDER BY count DESC
           LIMIT 10"#,
    )
    .bind(&current_user.tenant_id)
    .bind(start)
    .bind(end)
    .fetch_all(state.db.pool())
    .await
    .unwrap_or_default();

    let mut violations_by_endpoint = HashMap::new();
    for (endpoint, count) in &violations {
        violations_by_endpoint.insert(endpoint.clone(), *count);
    }

    // Top blocked IPs
    let top_blocked: Vec<(String, i64, DateTime<Utc>)> = sqlx::query_as(
        r#"SELECT ip_address, violation_count, blocked_at
           FROM blocked_ips
           WHERE tenant_id = $1
           ORDER BY violation_count DESC
           LIMIT 10"#,
    )
    .bind(&current_user.tenant_id)
    .fetch_all(state.db.pool())
    .await
    .unwrap_or_default();

    // Repeat offenders
    let repeat_offenders: Vec<(String, i64, DateTime<Utc>, DateTime<Utc>)> = sqlx::query_as(
        r#"SELECT ip_address, COUNT(*) as count, MIN(timestamp) as first, MAX(timestamp) as last
           FROM rate_limit_violations
           WHERE tenant_id = $1 AND timestamp >= $2
           GROUP BY ip_address
           HAVING COUNT(*) >= 5
           ORDER BY count DESC
           LIMIT 10"#,
    )
    .bind(&current_user.tenant_id)
    .bind(start)
    .fetch_all(state.db.pool())
    .await
    .unwrap_or_default();

    Ok(Json(RateLimitMetrics {
        period: MetricsPeriod {
            start: start.to_rfc3339(),
            end: end.to_rfc3339(),
            hours: 24,
        },
        requests: RequestMetrics {
            total: total_requests,
            allowed: total_requests, // Simplified
            blocked: violations.iter().map(|(_, c)| *c).sum(),
            average_latency_ms: 0.0,
        },
        violations: ViolationMetrics {
            total: violations.iter().map(|(_, c)| *c).sum(),
            by_endpoint: violations_by_endpoint,
            by_ip: HashMap::new(), // Would populate from query
            repeat_offenders: repeat_offenders
                .into_iter()
                .map(|(ip, count, first, last)| RepeatOffender {
                    ip_address: ip,
                    violation_count: count,
                    first_violation: first.to_rfc3339(),
                    last_violation: last.to_rfc3339(),
                })
                .collect(),
        },
        top_blocked_ips: top_blocked
            .into_iter()
            .map(|(ip, count, last)| TopBlockedIp {
                ip_address: ip,
                block_count: count,
                last_blocked: last.to_rfc3339(),
            })
            .collect(),
        hourly_distribution: vec![], // Would calculate from time-series data
    }))
}

// ============ Helper Functions ============

/// Get tenant rate limit config from database or return default
async fn get_tenant_rate_limit_config(
    state: &AppState,
    tenant_id: &str,
) -> Result<RateLimitConfig, ApiError> {
    let row = sqlx::query_as::<_, (i32, i32, i32, i32, bool, i32, i32)>(
        r#"SELECT api_per_minute, auth_per_minute, window_seconds, burst_allowance,
                  auto_block_enabled, auto_block_threshold, auto_block_duration_minutes
           FROM tenant_rate_limit_configs
           WHERE tenant_id = $1"#,
    )
    .bind(tenant_id)
    .fetch_optional(state.db.pool())
    .await
    .map_err(|_| ApiError::internal())?;

    match row {
        Some((
            api_per_minute,
            auth_per_minute,
            window_seconds,
            burst_allowance,
            auto_block_enabled,
            auto_block_threshold,
            auto_block_duration_minutes,
        )) => Ok(RateLimitConfig {
            api_per_minute: api_per_minute as u32,
            auth_per_minute: auth_per_minute as u32,
            window_seconds: window_seconds as u64,
            burst_allowance: burst_allowance as u32,
            user_multiplier: 2.0,
            ip_multiplier: 1.0,
            auto_block_enabled,
            auto_block_threshold: auto_block_threshold as u32,
            auto_block_duration_minutes: auto_block_duration_minutes as i64,
        }),
        None => Ok(RateLimitConfig {
            api_per_minute: state.config.rate_limit.api_per_minute,
            auth_per_minute: state.config.rate_limit.auth_per_minute,
            window_seconds: state.config.rate_limit.window_seconds,
            burst_allowance: 10,
            user_multiplier: 2.0,
            ip_multiplier: 1.0,
            auto_block_enabled: true,
            auto_block_threshold: 10,
            auto_block_duration_minutes: 60,
        }),
    }
}
