//! Admin Analytics Routes
//!
//! Provides comprehensive analytics endpoints for admin dashboards.
//! All endpoints require admin authentication.

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
    Extension, Router,
};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

use crate::analytics::{
    AnalyticsService, ExportFormat, TimeInterval,
    models::*,
};
use crate::routes::ApiError;
use crate::state::AppState;
use crate::state::CurrentUser;

/// Analytics routes
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/analytics/dashboard", get(get_dashboard))
        .route("/analytics/logins", get(get_login_analytics))
        .route("/analytics/users", get(get_user_analytics))
        .route("/analytics/mfa", get(get_mfa_analytics))
        .route("/analytics/devices", get(get_device_analytics))
        .route("/analytics/geography", get(get_geographic_analytics))
        .route("/analytics/security", get(get_security_analytics))
        .route("/analytics/sessions", get(get_session_analytics))
        .route("/analytics/realtime", get(get_realtime_metrics))
        .route("/analytics/export", get(export_analytics))
        .route("/analytics/trends", get(get_trend_analysis))
}

// ============ Request/Response Types ============

#[derive(Debug, Deserialize)]
struct AnalyticsQuery {
    /// Start date (ISO 8601 format)
    start_date: Option<DateTime<Utc>>,
    /// End date (ISO 8601 format)
    end_date: Option<DateTime<Utc>>,
    /// Aggregation interval: hour, day, week, month
    #[serde(default = "default_interval")]
    interval: String,
}

fn default_interval() -> String {
    "day".to_string()
}

impl AnalyticsQuery {
    /// Get or default start date (defaults to 30 days ago)
    fn start_date(&self) -> DateTime<Utc> {
        self.start_date.unwrap_or_else(|| Utc::now() - Duration::days(30))
    }

    /// Get or default end date (defaults to now)
    fn end_date(&self) -> DateTime<Utc> {
        self.end_date.unwrap_or_else(Utc::now)
    }

    /// Parse interval
    fn interval(&self) -> TimeInterval {
        self.interval
            .parse::<TimeInterval>()
            .unwrap_or(TimeInterval::Day)
    }
}

#[derive(Debug, Deserialize)]
struct ExportQuery {
    /// Export format: csv, json
    #[serde(default = "default_export_format")]
    format: String,
    /// Start date
    start_date: Option<DateTime<Utc>>,
    /// End date
    end_date: Option<DateTime<Utc>>,
    /// Metrics to include (comma-separated)
    metrics: Option<String>,
}

fn default_export_format() -> String {
    "json".to_string()
}

/// Dashboard response
#[derive(Debug, Serialize)]
struct DashboardResponse {
    period: PeriodResponse,
    summary: SummaryResponse,
    logins: LoginSummaryResponse,
    users: UserSummaryResponse,
    mfa: MfaSummaryResponse,
    security: SecuritySummaryResponse,
    current_active_sessions: i64,
}

#[derive(Debug, Serialize)]
struct PeriodResponse {
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    days: i64,
}

#[derive(Debug, Serialize)]
struct SummaryResponse {
    total_logins: i64,
    total_users: i64,
    new_users: i64,
    avg_daily_active_users: i64,
    login_success_rate: f64,
}

#[derive(Debug, Serialize)]
struct LoginSummaryResponse {
    total: i64,
    successful: i64,
    failed: i64,
    success_rate: f64,
    trend: Vec<TrendPoint>,
    by_method: HashMap<String, i64>,
}

#[derive(Debug, Serialize)]
struct UserSummaryResponse {
    new: i64,
    active: i64,
    retention_rate: f64,
    trend: Vec<TrendPoint>,
}

#[derive(Debug, Serialize)]
struct MfaSummaryResponse {
    adoption_rate: f64,
    enrolled_users: i64,
    by_method: HashMap<String, i64>,
}

#[derive(Debug, Serialize)]
struct SecuritySummaryResponse {
    failed_logins: i64,
    account_lockouts: i64,
    suspicious_activities: i64,
    risk_score: u32,
    risk_level: String,
}

#[derive(Debug, Serialize)]
struct TrendPoint {
    timestamp: DateTime<Utc>,
    value: i64,
    label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<serde_json::Value>,
}

/// Login analytics response
#[derive(Debug, Serialize)]
struct LoginAnalyticsResponse {
    period: PeriodResponse,
    summary: LoginSummary,
    trend: Vec<TrendPoint>,
    by_method: HashMap<String, i64>,
    by_hour: HashMap<u8, i64>,
    by_day_of_week: HashMap<String, i64>,
    top_failed_ips: Vec<FailedIpResponse>,
}

#[derive(Debug, Serialize)]
struct LoginSummary {
    total: i64,
    successful: i64,
    failed: i64,
    success_rate: f64,
    unique_users: i64,
}

#[derive(Debug, Serialize)]
struct FailedIpResponse {
    ip_address: String,
    failed_attempts: i64,
    last_attempt: Option<DateTime<Utc>>,
}

/// User analytics response
#[derive(Debug, Serialize)]
struct UserAnalyticsResponse {
    period: PeriodResponse,
    summary: UserSummary,
    trend: Vec<TrendPoint>,
    retention: RetentionMetrics,
    signup_sources: HashMap<String, i64>,
}

#[derive(Debug, Serialize)]
struct UserSummary {
    total: i64,
    new: i64,
    active: i64,
    churned: i64,
    growth_rate: f64,
}

#[derive(Debug, Serialize)]
struct RetentionMetrics {
    day_1: f64,
    day_7: f64,
    day_30: f64,
}

/// MFA analytics response
#[derive(Debug, Serialize)]
struct MfaAnalyticsResponse {
    period: PeriodResponse,
    adoption: MfaAdoption,
    usage: MfaUsage,
    by_method: Vec<MfaMethodStats>,
}

#[derive(Debug, Serialize)]
struct MfaAdoption {
    rate: f64,
    enrolled_users: i64,
    total_users: i64,
}

#[derive(Debug, Serialize)]
struct MfaUsage {
    total_attempts: i64,
    successful: i64,
    failed: i64,
    success_rate: f64,
}

#[derive(Debug, Serialize)]
struct MfaMethodStats {
    method: String,
    enrollments: i64,
    usage_count: i64,
    success_rate: f64,
}

/// Device analytics response
#[derive(Debug, Serialize)]
struct DeviceAnalyticsResponse {
    period: PeriodResponse,
    browsers: Vec<DeviceCategory>,
    operating_systems: Vec<DeviceCategory>,
    device_types: Vec<DeviceCategory>,
    top_combinations: Vec<DeviceCombination>,
}

#[derive(Debug, Serialize)]
struct DeviceCategory {
    name: String,
    count: i64,
    percentage: f64,
}

#[derive(Debug, Serialize)]
struct DeviceCombination {
    browser: String,
    os: String,
    device_type: String,
    count: i64,
}

/// Geographic analytics response
#[derive(Debug, Serialize)]
struct GeographicAnalyticsResponse {
    period: PeriodResponse,
    summary: GeoSummary,
    countries: Vec<CountryStats>,
    top_cities: Vec<CityStats>,
}

#[derive(Debug, Serialize)]
struct GeoSummary {
    total_countries: usize,
    top_country: Option<String>,
    concentration_index: f64,
}

#[derive(Debug, Serialize)]
struct CountryStats {
    code: String,
    name: String,
    login_count: i64,
    unique_users: i64,
    percentage: f64,
}

#[derive(Debug, Serialize)]
struct CityStats {
    name: String,
    country: String,
    login_count: i64,
}

/// Security analytics response
#[derive(Debug, Serialize)]
struct SecurityAnalyticsResponse {
    period: PeriodResponse,
    risk_assessment: RiskAssessment,
    failed_logins: FailedLoginStats,
    lockouts: LockoutStats,
    suspicious_activities: Vec<SuspiciousActivity>,
    password_security: PasswordSecurity,
}

#[derive(Debug, Serialize)]
struct RiskAssessment {
    score: u32,
    level: String,
    trend: String,
}

#[derive(Debug, Serialize)]
struct FailedLoginStats {
    total: i64,
    unique_ips: i64,
    top_ips: Vec<FailedIpResponse>,
    by_username: Vec<UsernameFailureStats>,
}

#[derive(Debug, Serialize)]
struct UsernameFailureStats {
    username: String,
    failed_attempts: i64,
}

#[derive(Debug, Serialize)]
struct LockoutStats {
    total: i64,
    active: i64,
    average_duration_minutes: f64,
}

#[derive(Debug, Serialize)]
struct SuspiciousActivity {
    activity_type: String,
    count: i64,
    description: String,
}

#[derive(Debug, Serialize)]
struct PasswordSecurity {
    breaches_detected: i64,
    weak_passwords: i64,
    policy_violations: i64,
}

/// Session analytics response
#[derive(Debug, Serialize)]
struct SessionAnalyticsResponse {
    period: PeriodResponse,
    summary: SessionSummary,
    duration_stats: DurationStats,
    trend: Vec<TrendPoint>,
    by_device: HashMap<String, i64>,
}

#[derive(Debug, Serialize)]
struct SessionSummary {
    total_created: i64,
    total_revoked: i64,
    total_expired: i64,
    currently_active: i64,
    average_per_user: f64,
}

#[derive(Debug, Serialize)]
struct DurationStats {
    average_minutes: f64,
    median_minutes: f64,
    max_minutes: i64,
    min_minutes: i64,
}

/// Real-time metrics response
#[derive(Debug, Serialize)]
struct RealTimeMetricsResponse {
    timestamp: DateTime<Utc>,
    active_sessions: i64,
    logins_last_minute: i64,
    logins_last_5_minutes: i64,
    logins_last_hour: i64,
    current_auth_rate: f64,
    top_active_users: Vec<RealTimeActiveUser>,
    system_health: SystemHealth,
}

#[derive(Debug, Serialize)]
struct RealTimeActiveUser {
    user_id: String,
    email: String,
    session_count: i32,
    last_activity: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
struct SystemHealth {
    status: String,
    average_response_time_ms: f64,
    error_rate: f64,
}

/// Trend analysis response
#[derive(Debug, Serialize)]
struct TrendAnalysisResponse {
    period: PeriodResponse,
    comparisons: Vec<PeriodComparison>,
    insights: Vec<TrendInsight>,
}

#[derive(Debug, Serialize)]
struct PeriodComparison {
    metric: String,
    current: f64,
    previous: f64,
    change_percent: f64,
    trend: String,
}

#[derive(Debug, Serialize)]
struct TrendInsight {
    category: String,
    message: String,
    severity: String,
}

// ============ Handlers ============

/// Get dashboard overview
async fn get_dashboard(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Query(query): Query<AnalyticsQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let tenant_id = parse_tenant_id(&current_user.tenant_id)?;
    
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let start_date = query.start_date();
    let end_date = query.end_date();
    let days = (end_date - start_date).num_days();

    let analytics = AnalyticsService::new(state.db.pool().clone());

    let overview = analytics
        .get_dashboard_overview(tenant_id, start_date, end_date)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to get dashboard overview");
            ApiError::Internal
        })?;

    let response = DashboardResponse {
        period: PeriodResponse {
            start: overview.period.start,
            end: overview.period.end,
            days,
        },
        summary: SummaryResponse {
            total_logins: overview.summary.total_logins,
            total_users: overview.summary.total_users,
            new_users: overview.summary.new_users,
            avg_daily_active_users: overview.summary.avg_daily_active_users,
            login_success_rate: overview.summary.login_success_rate,
        },
        logins: LoginSummaryResponse {
            total: overview.logins.total,
            successful: overview.logins.successful,
            failed: overview.logins.failed,
            success_rate: overview.logins.success_rate,
            trend: overview
                .logins
                .trend
                .into_iter()
                .map(|t| TrendPoint {
                    timestamp: t.timestamp,
                    value: t.value,
                    label: t.label,
                    metadata: t.metadata,
                })
                .collect(),
            by_method: overview.logins.by_method,
        },
        users: UserSummaryResponse {
            new: overview.users.new,
            active: overview.users.active,
            retention_rate: overview.users.retention_rate,
            trend: overview
                .users
                .trend
                .into_iter()
                .map(|t| TrendPoint {
                    timestamp: t.timestamp,
                    value: t.value,
                    label: t.label,
                    metadata: t.metadata,
                })
                .collect(),
        },
        mfa: MfaSummaryResponse {
            adoption_rate: overview.mfa.adoption_rate,
            enrolled_users: overview.mfa.enrolled_users,
            by_method: overview.mfa.by_method,
        },
        security: SecuritySummaryResponse {
            failed_logins: overview.security.failed_logins,
            account_lockouts: overview.security.account_lockouts,
            suspicious_activities: overview.security.suspicious_activities,
            risk_score: overview.security.risk_score,
            risk_level: overview.security.risk_level,
        },
        current_active_sessions: overview.current_active_sessions,
    };

    Ok((StatusCode::OK, axum::Json(response)))
}

/// Get login analytics
async fn get_login_analytics(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Query(query): Query<AnalyticsQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let tenant_id = parse_tenant_id(&current_user.tenant_id)?;
    
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let start_date = query.start_date();
    let end_date = query.end_date();
    let days = (end_date - start_date).num_days();

    let analytics = AnalyticsService::new(state.db.pool().clone());

    let login_metrics = analytics
        .get_login_metrics(tenant_id, start_date, end_date)
        .await
        .map_err(|_| ApiError::Internal)?;

    let failed_ips: Vec<FailedIpResponse> = login_metrics
        .by_hour  // Placeholder - security metrics should provide this
        .iter()
        .map(|(ip, count)| FailedIpResponse {
            ip_address: format!("{:?}", ip),
            failed_attempts: *count,
            last_attempt: None,
        })
        .collect();

    let response = LoginAnalyticsResponse {
        period: PeriodResponse {
            start: start_date,
            end: end_date,
            days,
        },
        summary: LoginSummary {
            total: login_metrics.total,
            successful: login_metrics.successful,
            failed: login_metrics.failed,
            success_rate: login_metrics.success_rate() * 100.0,
            unique_users: login_metrics.unique_users,
        },
        trend: login_metrics
            .trend
            .into_iter()
            .map(|t| TrendPoint {
                timestamp: t.timestamp,
                value: t.value,
                label: t.label,
                metadata: t.metadata,
            })
            .collect(),
        by_method: login_metrics.by_method,
        by_hour: login_metrics.by_hour,
        by_day_of_week: login_metrics.by_day_of_week,
        top_failed_ips: failed_ips,
    };

    Ok((StatusCode::OK, axum::Json(response)))
}

/// Get user analytics
async fn get_user_analytics(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Query(query): Query<AnalyticsQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let tenant_id = parse_tenant_id(&current_user.tenant_id)?;
    
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let start_date = query.start_date();
    let end_date = query.end_date();
    let days = (end_date - start_date).num_days();

    let analytics = AnalyticsService::new(state.db.pool().clone());

    let user_metrics = analytics
        .get_user_metrics(tenant_id, start_date, end_date)
        .await
        .map_err(|_| ApiError::Internal)?;

    let response = UserAnalyticsResponse {
        period: PeriodResponse {
            start: start_date,
            end: end_date,
            days,
        },
        summary: UserSummary {
            total: user_metrics.total_users,
            new: user_metrics.new_signups,
            active: user_metrics.active_users,
            churned: user_metrics.churned_users,
            growth_rate: user_metrics.growth_rate,
        },
        trend: user_metrics
            .trend
            .into_iter()
            .map(|t| TrendPoint {
                timestamp: t.timestamp,
                value: t.value,
                label: t.label,
                metadata: t.metadata,
            })
            .collect(),
        retention: RetentionMetrics {
            day_1: 0.0,
            day_7: user_metrics.retention_rate * 100.0,
            day_30: 0.0,
        },
        signup_sources: user_metrics.signup_sources,
    };

    Ok((StatusCode::OK, axum::Json(response)))
}

/// Get MFA analytics
async fn get_mfa_analytics(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Query(query): Query<AnalyticsQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let tenant_id = parse_tenant_id(&current_user.tenant_id)?;
    
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let start_date = query.start_date();
    let end_date = query.end_date();
    let days = (end_date - start_date).num_days();

    let analytics = AnalyticsService::new(state.db.pool().clone());

    let mfa_metrics = analytics
        .get_mfa_metrics(tenant_id, start_date, end_date)
        .await
        .map_err(|_| ApiError::Internal)?;

    let by_method: Vec<MfaMethodStats> = mfa_metrics
        .by_method
        .into_iter()
        .map(|(method, count)| MfaMethodStats {
            method,
            enrollments: count,
            usage_count: 0,
            success_rate: 0.0,
        })
        .collect();

    let total_users = mfa_metrics.total_enrollments as f64 / mfa_metrics.adoption_rate.max(0.0001);

    let response = MfaAnalyticsResponse {
        period: PeriodResponse {
            start: start_date,
            end: end_date,
            days,
        },
        adoption: MfaAdoption {
            rate: mfa_metrics.adoption_rate * 100.0,
            enrolled_users: mfa_metrics.total_enrollments,
            total_users: total_users as i64,
        },
        usage: MfaUsage {
            total_attempts: mfa_metrics.total_attempts,
            successful: mfa_metrics.successful_attempts,
            failed: mfa_metrics.failed_attempts,
            success_rate: mfa_metrics.success_rate * 100.0,
        },
        by_method,
    };

    Ok((StatusCode::OK, axum::Json(response)))
}

/// Get device analytics
async fn get_device_analytics(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Query(query): Query<AnalyticsQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let tenant_id = parse_tenant_id(&current_user.tenant_id)?;
    
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let start_date = query.start_date();
    let end_date = query.end_date();
    let days = (end_date - start_date).num_days();

    let analytics = AnalyticsService::new(state.db.pool().clone());

    let device_metrics = analytics
        .get_device_metrics(tenant_id, start_date, end_date)
        .await
        .map_err(|_| ApiError::Internal)?;

    let total: i64 = device_metrics.by_browser.values().sum();

    let browsers: Vec<DeviceCategory> = device_metrics
        .by_browser
        .into_iter()
        .map(|(name, count)| DeviceCategory {
            name,
            count,
            percentage: if total > 0 {
                count as f64 / total as f64 * 100.0
            } else {
                0.0
            },
        })
        .collect();

    let os_total: i64 = device_metrics.by_os.values().sum();
    let operating_systems: Vec<DeviceCategory> = device_metrics
        .by_os
        .into_iter()
        .map(|(name, count)| DeviceCategory {
            name,
            count,
            percentage: if os_total > 0 {
                count as f64 / os_total as f64 * 100.0
            } else {
                0.0
            },
        })
        .collect();

    let device_total: i64 = device_metrics.by_device_type.values().sum();
    let device_types: Vec<DeviceCategory> = device_metrics
        .by_device_type
        .into_iter()
        .map(|(name, count)| DeviceCategory {
            name,
            count,
            percentage: if device_total > 0 {
                count as f64 / device_total as f64 * 100.0
            } else {
                0.0
            },
        })
        .collect();

    let top_combinations = device_metrics
        .top_combinations
        .into_iter()
        .map(|c| DeviceCombination {
            browser: c.browser,
            os: c.os,
            device_type: c.device_type,
            count: c.count,
        })
        .collect();

    let response = DeviceAnalyticsResponse {
        period: PeriodResponse {
            start: start_date,
            end: end_date,
            days,
        },
        browsers,
        operating_systems,
        device_types,
        top_combinations,
    };

    Ok((StatusCode::OK, axum::Json(response)))
}

/// Get geographic analytics
async fn get_geographic_analytics(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Query(query): Query<AnalyticsQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let tenant_id = parse_tenant_id(&current_user.tenant_id)?;
    
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let start_date = query.start_date();
    let end_date = query.end_date();
    let days = (end_date - start_date).num_days();

    let analytics = AnalyticsService::new(state.db.pool().clone());

    let geo_metrics = analytics
        .get_geographic_metrics(tenant_id, start_date, end_date)
        .await
        .map_err(|_| ApiError::Internal)?;

    let total_logins: i64 = geo_metrics.countries.iter().map(|c| c.login_count).sum();

    let countries: Vec<CountryStats> = geo_metrics
        .countries
        .into_iter()
        .map(|c| CountryStats {
            code: c.country_code.clone(),
            name: c.country_name,
            login_count: c.login_count,
            unique_users: c.unique_users,
            percentage: if total_logins > 0 {
                c.login_count as f64 / total_logins as f64 * 100.0
            } else {
                0.0
            },
        })
        .collect();

    let top_country = countries.first().map(|c| c.name.clone());

    let top_cities = geo_metrics
        .top_cities
        .into_iter()
        .map(|c| CityStats {
            name: c.city_name,
            country: c.country_code,
            login_count: c.login_count,
        })
        .collect();

    let response = GeographicAnalyticsResponse {
        period: PeriodResponse {
            start: start_date,
            end: end_date,
            days,
        },
        summary: GeoSummary {
            total_countries: geo_metrics.total_countries,
            top_country,
            concentration_index: geo_metrics.concentration_index,
        },
        countries,
        top_cities,
    };

    Ok((StatusCode::OK, axum::Json(response)))
}

/// Get security analytics
async fn get_security_analytics(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Query(query): Query<AnalyticsQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let tenant_id = parse_tenant_id(&current_user.tenant_id)?;
    
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let start_date = query.start_date();
    let end_date = query.end_date();
    let days = (end_date - start_date).num_days();

    let analytics = AnalyticsService::new(state.db.pool().clone());

    let security_metrics = analytics
        .get_security_metrics(tenant_id, start_date, end_date)
        .await
        .map_err(|_| ApiError::Internal)?;

    let failed_ips: Vec<FailedIpResponse> = security_metrics
        .failed_login_ips
        .into_iter()
        .map(|ip| FailedIpResponse {
            ip_address: ip.ip_address,
            failed_attempts: ip.failed_attempts,
            last_attempt: ip.last_attempt,
        })
        .collect();

    let by_username = security_metrics
        .failed_logins_by_username
        .into_iter()
        .map(|u| UsernameFailureStats {
            username: u.username,
            failed_attempts: u.failed_attempts,
        })
        .collect();

    let response = SecurityAnalyticsResponse {
        period: PeriodResponse {
            start: start_date,
            end: end_date,
            days,
        },
        risk_assessment: RiskAssessment {
            score: security_metrics.risk_score,
            level: security_metrics.risk_level.to_string(),
            trend: "stable".to_string(),
        },
        failed_logins: FailedLoginStats {
            total: security_metrics.failed_logins,
            unique_ips: failed_ips.len() as i64,
            top_ips: failed_ips,
            by_username,
        },
        lockouts: LockoutStats {
            total: security_metrics.account_lockouts,
            active: security_metrics.active_lockouts,
            average_duration_minutes: 0.0,
        },
        suspicious_activities: vec![
            SuspiciousActivity {
                activity_type: "suspicious_login".to_string(),
                count: security_metrics.suspicious_activities,
                description: "Login attempts flagged as suspicious".to_string(),
            },
        ],
        password_security: PasswordSecurity {
            breaches_detected: security_metrics.password_breaches_detected,
            weak_passwords: security_metrics.weak_passwords,
            policy_violations: security_metrics.policy_violations,
        },
    };

    Ok((StatusCode::OK, axum::Json(response)))
}

/// Get session analytics
async fn get_session_analytics(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Query(query): Query<AnalyticsQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let tenant_id = parse_tenant_id(&current_user.tenant_id)?;
    
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let start_date = query.start_date();
    let end_date = query.end_date();
    let days = (end_date - start_date).num_days();

    // Get session counts
    let total_sessions: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*) FROM sessions 
           WHERE tenant_id = $1 
             AND created_at >= $2 
             AND created_at <= $3"#,
    )
    .bind(&current_user.tenant_id)
    .bind(&start_date)
    .bind(&end_date)
    .fetch_one(state.db.pool())
    .await
    .map_err(|_| ApiError::Internal)?;

    let active_sessions: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*) FROM sessions 
           WHERE tenant_id = $1 
             AND status = 'active' 
             AND expires_at > NOW()"#,
    )
    .bind(&current_user.tenant_id)
    .fetch_one(state.db.pool())
    .await
    .map_err(|_| ApiError::Internal)?;

    let total_users: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM users WHERE tenant_id = $1"
    )
    .bind(&current_user.tenant_id)
    .fetch_one(state.db.pool())
    .await
    .map_err(|_| ApiError::Internal)?;

    let response = SessionAnalyticsResponse {
        period: PeriodResponse {
            start: start_date,
            end: end_date,
            days,
        },
        summary: SessionSummary {
            total_created: total_sessions,
            total_revoked: 0,
            total_expired: 0,
            currently_active: active_sessions,
            average_per_user: if total_users > 0 {
                total_sessions as f64 / total_users as f64
            } else {
                0.0
            },
        },
        duration_stats: DurationStats {
            average_minutes: 0.0,
            median_minutes: 0.0,
            max_minutes: 0,
            min_minutes: 0,
        },
        trend: Vec::new(),
        by_device: HashMap::new(),
    };

    Ok((StatusCode::OK, axum::Json(response)))
}

/// Get real-time metrics
async fn get_realtime_metrics(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<impl IntoResponse, ApiError> {
    let tenant_id = parse_tenant_id(&current_user.tenant_id)?;
    
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let now = Utc::now();
    let one_minute_ago = now - Duration::minutes(1);
    let five_minutes_ago = now - Duration::minutes(5);
    let one_hour_ago = now - Duration::hours(1);

    // Get active sessions
    let active_sessions: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*) FROM sessions 
           WHERE tenant_id = $1 
             AND status = 'active' 
             AND expires_at > NOW()"#,
    )
    .bind(&current_user.tenant_id)
    .fetch_one(state.db.pool())
    .await
    .map_err(|_| ApiError::Internal)?;

    // Get logins in last minute
    let logins_last_minute: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*) FROM analytics_events
           WHERE tenant_id = $1 
             AND event_type = 'login'
             AND created_at >= $2"#,
    )
    .bind(tenant_id)
    .bind(&one_minute_ago)
    .fetch_one(state.db.pool())
    .await
    .map_err(|_| ApiError::Internal)?;

    // Get logins in last 5 minutes
    let logins_last_5_minutes: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*) FROM analytics_events
           WHERE tenant_id = $1 
             AND event_type = 'login'
             AND created_at >= $2"#,
    )
    .bind(tenant_id)
    .bind(&five_minutes_ago)
    .fetch_one(state.db.pool())
    .await
    .map_err(|_| ApiError::Internal)?;

    // Get logins in last hour
    let logins_last_hour: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*) FROM analytics_events
           WHERE tenant_id = $1 
             AND event_type = 'login'
             AND created_at >= $2"#,
    )
    .bind(tenant_id)
    .bind(&one_hour_ago)
    .fetch_one(state.db.pool())
    .await
    .map_err(|_| ApiError::Internal)?;

    // Calculate auth rate (logins per minute)
    let auth_rate = logins_last_5_minutes as f64 / 5.0;

    // Get top active users
    let top_users = sqlx::query(
        r#"SELECT 
            s.user_id,
            u.email,
            COUNT(*) as session_count,
            MAX(s.last_activity_at) as last_activity
           FROM sessions s
           JOIN users u ON s.user_id = u.id
           WHERE s.tenant_id = $1 
             AND s.status = 'active'
             AND s.expires_at > NOW()
           GROUP BY s.user_id, u.email
           ORDER BY session_count DESC
           LIMIT 10"#,
    )
    .bind(&current_user.tenant_id)
    .fetch_all(state.db.pool())
    .await
    .map_err(|_| ApiError::Internal)?;

    let top_active_users: Vec<RealTimeActiveUser> = top_users
        .into_iter()
        .map(|row| {
            let user_id: String = row.try_get("user_id").unwrap_or_default();
            let email: String = row.try_get("email").unwrap_or_default();
            let session_count: i64 = row.try_get("session_count").unwrap_or(0);
            let last_activity: Option<DateTime<Utc>> = row.try_get("last_activity").ok();

            RealTimeActiveUser {
                user_id,
                email,
                session_count: session_count as i32,
                last_activity: last_activity.unwrap_or(now),
            }
        })
        .collect();

    let response = RealTimeMetricsResponse {
        timestamp: now,
        active_sessions,
        logins_last_minute,
        logins_last_5_minutes,
        logins_last_hour,
        current_auth_rate: auth_rate,
        top_active_users,
        system_health: SystemHealth {
            status: "healthy".to_string(),
            average_response_time_ms: 0.0,
            error_rate: 0.0,
        },
    };

    Ok((StatusCode::OK, axum::Json(response)))
}

/// Export analytics data
async fn export_analytics(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Query(query): Query<ExportQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let tenant_id = parse_tenant_id(&current_user.tenant_id)?;
    
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let start_date = query.start_date.unwrap_or_else(|| Utc::now() - Duration::days(30));
    let end_date = query.end_date.unwrap_or_else(Utc::now);

    let format = query
        .format
        .parse::<ExportFormat>()
        .map_err(|_| ApiError::BadRequest("Invalid export format".to_string()))?;

    let analytics = AnalyticsService::new(state.db.pool().clone());

    // Get all metrics
    let dashboard = analytics
        .get_dashboard_overview(tenant_id, start_date, end_date)
        .await
        .map_err(|_| ApiError::Internal)?;

    match format {
        ExportFormat::Json => {
            let json_data = serde_json::to_string_pretty(&dashboard).map_err(|_| ApiError::Internal)?;

            let headers = [
                ("Content-Type", "application/json"),
                (
                    "Content-Disposition",
                    "attachment; filename=\"analytics_export.json\"",
                ),
            ];

            Ok((StatusCode::OK, headers, json_data).into_response())
        }
        ExportFormat::Csv => {
            // Build CSV data
            let mut csv_data = String::from(
                "Metric,Value\n",
            );

            csv_data.push_str(&format!(
                "Total Logins,{}\n",
                dashboard.logins.total,
            ));
            csv_data.push_str(&format!(
                "Successful Logins,{}\n",
                dashboard.logins.successful,
            ));
            csv_data.push_str(&format!(
                "Failed Logins,{}\n",
                dashboard.logins.failed,
            ));
            csv_data.push_str(&format!(
                "New Users,{}\n",
                dashboard.users.new,
            ));
            csv_data.push_str(&format!(
                "Active Users,{}\n",
                dashboard.users.active,
            ));
            csv_data.push_str(&format!(
                "MFA Adoption Rate,{}%\n",
                dashboard.mfa.adoption_rate,
            ));

            let headers = [
                ("Content-Type", "text/csv"),
                (
                    "Content-Disposition",
                    "attachment; filename=\"analytics_export.csv\"",
                ),
            ];

            Ok((StatusCode::OK, headers, csv_data).into_response())
        }
    }
}

/// Get trend analysis
async fn get_trend_analysis(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Query(query): Query<AnalyticsQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let tenant_id = parse_tenant_id(&current_user.tenant_id)?;
    
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let end_date = query.end_date();
    let start_date = query.start_date();
    let period_duration = end_date - start_date;
    let previous_start = start_date - period_duration;
    let previous_end = start_date;

    let analytics = AnalyticsService::new(state.db.pool().clone());

    // Get current period metrics
    let current_login = analytics
        .get_login_metrics(tenant_id, start_date, end_date)
        .await
        .map_err(|_| ApiError::Internal)?;

    // Get previous period metrics
    let previous_login = analytics
        .get_login_metrics(tenant_id, previous_start, previous_end)
        .await
        .map_err(|_| ApiError::Internal)?;

    // Calculate comparisons
    let login_change = if previous_login.total > 0 {
        (current_login.total - previous_login.total) as f64 / previous_login.total as f64 * 100.0
    } else {
        0.0
    };

    let comparisons = vec![
        PeriodComparison {
            metric: "total_logins".to_string(),
            current: current_login.total as f64,
            previous: previous_login.total as f64,
            change_percent: login_change,
            trend: if login_change > 5.0 {
                "up".to_string()
            } else if login_change < -5.0 {
                "down".to_string()
            } else {
                "stable".to_string()
            },
        },
    ];

    // Generate insights
    let mut insights = Vec::new();

    if login_change > 20.0 {
        insights.push(TrendInsight {
            category: "growth".to_string(),
            message: "Significant increase in login activity detected".to_string(),
            severity: "info".to_string(),
        });
    }

    if current_login.failed > current_login.successful {
        insights.push(TrendInsight {
            category: "security".to_string(),
            message: "More failed than successful logins - potential attack".to_string(),
            severity: "warning".to_string(),
        });
    }

    let days = (end_date - start_date).num_days();

    let response = TrendAnalysisResponse {
        period: PeriodResponse {
            start: start_date,
            end: end_date,
            days,
        },
        comparisons,
        insights,
    };

    Ok((StatusCode::OK, axum::Json(response)))
}

// ============ Helper Functions ============

/// Parse tenant ID string to UUID
fn parse_tenant_id(tenant_id_str: &str) -> Result<Uuid, ApiError> {
    Uuid::parse_str(tenant_id_str)
        .map_err(|_| ApiError::BadRequest("Invalid tenant ID format".to_string()))
}
