//! Security Dashboard Routes
//!
//! User-facing security dashboard endpoints for viewing security score,
//! alerts, recommendations, and MFA statistics.

use axum::{
    extract::{Extension, Path, State},
    routing::{get, put},
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use crate::routes::ApiError;
use crate::state::{AppState, CurrentUser};

/// Security score response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityScoreResponse {
    #[serde(rename = "overallScore")]
    pub overall_score: i32,
    #[serde(rename = "mfaScore")]
    pub mfa_score: i32,
    #[serde(rename = "passwordScore")]
    pub password_score: i32,
    #[serde(rename = "sessionScore")]
    pub session_score: i32,
    #[serde(rename = "deviceScore")]
    pub device_score: i32,
    #[serde(rename = "lastUpdated")]
    pub last_updated: DateTime<Utc>,
}

/// Security alert
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct SecurityAlert {
    pub id: String,
    pub severity: String,
    pub category: String,
    pub title: String,
    pub description: String,
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    pub status: String,
    #[serde(rename = "relatedSessionId")]
    pub related_session_id: Option<String>,
    #[serde(rename = "relatedDeviceId")]
    pub related_device_id: Option<String>,
}

/// Security recommendation
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct SecurityRecommendation {
    pub id: String,
    pub priority: String,
    pub category: String,
    pub title: String,
    pub description: String,
    #[serde(rename = "actionText")]
    pub action_text: String,
    #[serde(rename = "actionRoute")]
    pub action_route: Option<String>,
    #[serde(rename = "isCompleted")]
    pub is_completed: bool,
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
}

/// MFA statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaStats {
    #[serde(rename = "totalUsers")]
    pub total_users: i64,
    #[serde(rename = "mfaEnabledUsers")]
    pub mfa_enabled_users: i64,
    #[serde(rename = "mfaAdoptionRate")]
    pub mfa_adoption_rate: f64,
    #[serde(rename = "factorsByType")]
    pub factors_by_type: Vec<FactorTypeStat>,
}

/// Factor type statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FactorTypeStat {
    #[serde(rename = "factorType")]
    pub factor_type: String,
    pub count: i64,
    pub percentage: f64,
}

/// Risk factors breakdown
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFactorsResponse {
    #[serde(rename = "weakPasswords")]
    pub weak_passwords: i64,
    #[serde(rename = "noMfaUsers")]
    pub no_mfa_users: i64,
    #[serde(rename = "suspiciousDevices")]
    pub suspicious_devices: i64,
    #[serde(rename = "failedLoginAttempts")]
    pub failed_login_attempts: i64,
    #[serde(rename = "untrustedDevices")]
    pub untrusted_devices: i64,
}

/// Alert list response
#[derive(Debug, Serialize)]
pub struct AlertListResponse {
    pub alerts: Vec<SecurityAlert>,
    pub total: usize,
    #[serde(rename = "unacknowledgedCount")]
    pub unacknowledged_count: i64,
}

/// Acknowledge alert request
#[derive(Debug, Deserialize)]
pub struct AcknowledgeAlertRequest {
    pub notes: Option<String>,
}

/// Acknowledge alert response
#[derive(Debug, Serialize)]
pub struct AcknowledgeAlertResponse {
    pub success: bool,
    pub message: String,
}

/// Create security dashboard routes
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/me/security/score", get(get_my_security_score))
        .route("/me/security/alerts", get(get_my_security_alerts))
        .route("/me/security/alerts/:alert_id/ack", put(acknowledge_my_alert))
        .route("/me/security/recommendations", get(get_my_recommendations))
        .route("/me/security/mfa-stats", get(get_my_mfa_stats))
        .route("/me/security/risk-factors", get(get_my_risk_factors))
}

/// Get security score for current user
async fn get_my_security_score(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<SecurityScoreResponse>, ApiError> {
    let user_id = Uuid::parse_str(&current_user.user_id)
        .map_err(|_| ApiError::bad_request("Invalid user ID"))?;
    let tenant_id = Uuid::parse_str(&current_user.tenant_id)
        .map_err(|_| ApiError::bad_request("Invalid tenant ID"))?;

    // Try to get from database first
    let score: Option<(i32, i32, i32, i32, i32, DateTime<Utc>)> = sqlx::query_as(
        r#"
        SELECT 
            overall_score,
            mfa_score,
            password_score,
            session_score,
            device_score,
            calculated_at
        FROM security_scores
        WHERE tenant_id = $1 AND user_id = $2
        ORDER BY calculated_at DESC
        LIMIT 1
        "#
    )
    .bind(tenant_id)
    .bind(user_id)
    .fetch_optional(state.db.pool())
    .await
    .map_err(|e| ApiError::internal_error(format!("Database error: {}", e)))?;

    if let Some((overall, mfa, password, session, device, updated)) = score {
        return Ok(Json(SecurityScoreResponse {
            overall_score: overall,
            mfa_score: mfa,
            password_score: password,
            session_score: session,
            device_score: device,
            last_updated: updated,
        }));
    }

    // Calculate scores from user data
    let mfa_score = calculate_mfa_score(&state, user_id, tenant_id).await?;
    let device_score = calculate_device_score(&state, user_id, tenant_id).await?;
    let session_score = calculate_session_score(&state, user_id, tenant_id).await?;
    let password_score = 80; // Default, would check password policy compliance

    let overall = (mfa_score + device_score + session_score + password_score) / 4;

    Ok(Json(SecurityScoreResponse {
        overall_score: overall,
        mfa_score,
        password_score,
        session_score,
        device_score,
        last_updated: Utc::now(),
    }))
}

/// Calculate MFA score based on enabled factors
async fn calculate_mfa_score(
    state: &AppState,
    user_id: Uuid,
    tenant_id: Uuid,
) -> Result<i32, ApiError> {
    let count: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*) 
        FROM mfa_factors 
        WHERE user_id = $1 AND tenant_id = $2 AND verified = true
        "#
    )
    .bind(user_id)
    .bind(tenant_id)
    .fetch_one(state.db.pool())
    .await
    .map_err(|e| ApiError::internal_error(format!("Database error: {}", e)))?;

    // Score: 0 factors = 20, 1 factor = 60, 2+ factors = 100
    Ok(match count.0 {
        0 => 20,
        1 => 60,
        _ => 100,
    })
}

/// Calculate device score based on trusted devices ratio
async fn calculate_device_score(
    state: &AppState,
    user_id: Uuid,
    tenant_id: Uuid,
) -> Result<i32, ApiError> {
    let stats: (i64, i64) = sqlx::query_as(
        r#"
        SELECT 
            COUNT(*) FILTER (WHERE is_trusted = true) as trusted,
            COUNT(*) as total
        FROM user_devices 
        WHERE user_id = $1 AND tenant_id = $2 AND is_active = true
        "#
    )
    .bind(user_id)
    .bind(tenant_id)
    .fetch_one(state.db.pool())
    .await
    .map_err(|e| ApiError::internal_error(format!("Database error: {}", e)))?;

    if stats.1 == 0 {
        return Ok(50); // Neutral score if no devices
    }

    Ok(((stats.0 as f64 / stats.1 as f64) * 100.0) as i32)
}

/// Calculate session score based on suspicious sessions
async fn calculate_session_score(
    state: &AppState,
    user_id: Uuid,
    tenant_id: Uuid,
) -> Result<i32, ApiError> {
    let stats: (i64, i64) = sqlx::query_as(
        r#"
        SELECT 
            COUNT(*) FILTER (WHERE is_suspicious = false OR is_suspicious IS NULL) as safe,
            COUNT(*) as total
        FROM sessions 
        WHERE user_id = $1 AND tenant_id = $2 AND status = 'active'
        "#
    )
    .bind(user_id)
    .bind(tenant_id)
    .fetch_one(state.db.pool())
    .await
    .map_err(|e| ApiError::internal_error(format!("Database error: {}", e)))?;

    if stats.1 == 0 {
        return Ok(100); // Perfect score if no active sessions
    }

    Ok(((stats.0 as f64 / stats.1 as f64) * 100.0) as i32)
}

/// Get security alerts for current user
async fn get_my_security_alerts(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<AlertListResponse>, ApiError> {
    let user_id = Uuid::parse_str(&current_user.user_id)
        .map_err(|_| ApiError::bad_request("Invalid user ID"))?;
    let tenant_id = Uuid::parse_str(&current_user.tenant_id)
        .map_err(|_| ApiError::bad_request("Invalid tenant ID"))?;

    let alerts: Vec<SecurityAlert> = sqlx::query_as::<_, SecurityAlert>(
        r#"
        SELECT 
            id::text as id,
            severity,
            category,
            title,
            description,
            created_at,
            status,
            related_session_id::text as related_session_id,
            related_device_id::text as related_device_id
        FROM security_alerts
        WHERE (user_id = $1 OR user_id IS NULL) AND tenant_id = $2
        ORDER BY 
            CASE severity 
                WHEN 'critical' THEN 1 
                WHEN 'high' THEN 2 
                WHEN 'medium' THEN 3 
                WHEN 'low' THEN 4 
                ELSE 5 
            END,
            created_at DESC
        LIMIT 50
        "#
    )
    .bind(user_id)
    .bind(tenant_id)
    .fetch_all(state.db.pool())
    .await
    .map_err(|e| ApiError::internal_error(format!("Database error: {}", e)))?;

    let unacknowledged: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*) 
        FROM security_alerts 
        WHERE (user_id = $1 OR user_id IS NULL) AND tenant_id = $2 AND status = 'open'
        "#
    )
    .bind(user_id)
    .bind(tenant_id)
    .fetch_one(state.db.pool())
    .await
    .map_err(|e| ApiError::internal_error(format!("Database error: {}", e)))?;

    let total = alerts.len();

    Ok(Json(AlertListResponse {
        alerts,
        total,
        unacknowledged_count: unacknowledged.0,
    }))
}

/// Acknowledge a security alert
async fn acknowledge_my_alert(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(alert_id): Path<Uuid>,
    Json(_req): Json<AcknowledgeAlertRequest>,
) -> Result<Json<AcknowledgeAlertResponse>, ApiError> {
    let user_id = Uuid::parse_str(&current_user.user_id)
        .map_err(|_| ApiError::bad_request("Invalid user ID"))?;
    let tenant_id = Uuid::parse_str(&current_user.tenant_id)
        .map_err(|_| ApiError::bad_request("Invalid tenant ID"))?;

    let result = sqlx::query(
        r#"
        UPDATE security_alerts 
        SET status = 'acknowledged', 
            acknowledged_by = $1, 
            acknowledged_at = NOW(),
            updated_at = NOW()
        WHERE id = $2 AND (user_id = $1 OR user_id IS NULL) AND tenant_id = $3
        "#
    )
    .bind(user_id)
    .bind(alert_id)
    .bind(tenant_id)
    .execute(state.db.pool())
    .await
    .map_err(|e| ApiError::internal_error(format!("Database error: {}", e)))?;

    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("Alert not found"));
    }

    Ok(Json(AcknowledgeAlertResponse {
        success: true,
        message: "Alert acknowledged".to_string(),
    }))
}

/// Get security recommendations for current user
async fn get_my_recommendations(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<Vec<SecurityRecommendation>>, ApiError> {
    let tenant_id = Uuid::parse_str(&current_user.tenant_id)
        .map_err(|_| ApiError::bad_request("Invalid tenant ID"))?;

    // Get recommendations from database
    let mut recommendations: Vec<SecurityRecommendation> = sqlx::query_as::<_, SecurityRecommendation>(
        r#"
        SELECT 
            id::text as id,
            priority,
            category,
            title,
            description,
            action_text,
            action_route,
            is_completed,
            created_at
        FROM security_recommendations
        WHERE tenant_id = $1 AND (is_completed = false OR completed_at > NOW() - INTERVAL '7 days')
        ORDER BY 
            CASE priority 
                WHEN 'critical' THEN 1 
                WHEN 'high' THEN 2 
                WHEN 'medium' THEN 3 
                ELSE 4 
            END,
            created_at DESC
        LIMIT 10
        "#
    )
    .bind(tenant_id)
    .fetch_all(state.db.pool())
    .await
    .map_err(|e| ApiError::internal_error(format!("Database error: {}", e)))?;

    // Generate dynamic recommendations based on user state
    let user_id = Uuid::parse_str(&current_user.user_id)
        .map_err(|_| ApiError::bad_request("Invalid user ID"))?;

    // Check if MFA is enabled
    let mfa_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM mfa_factors WHERE user_id = $1 AND verified = true"
    )
    .bind(user_id)
    .fetch_one(state.db.pool())
    .await
    .map_err(|e| ApiError::internal_error(format!("Database error: {}", e)))?;

    if mfa_count.0 == 0 && !recommendations.iter().any(|r| r.category == "mfa") {
        recommendations.push(SecurityRecommendation {
            id: "dynamic-mfa".to_string(),
            priority: "high".to_string(),
            category: "mfa".to_string(),
            title: "Enable Two-Factor Authentication".to_string(),
            description: "Add an extra layer of security to your account by enabling MFA".to_string(),
            action_text: "Enable MFA".to_string(),
            action_route: Some("/security".to_string()),
            is_completed: false,
            created_at: Utc::now(),
        });
    }

    // Check for untrusted devices
    let untrusted: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*) FROM user_devices 
        WHERE user_id = $1 AND is_trusted = false AND is_active = true
        "#
    )
    .bind(user_id)
    .fetch_one(state.db.pool())
    .await
    .map_err(|e| ApiError::internal_error(format!("Database error: {}", e)))?;

    if untrusted.0 > 0 && !recommendations.iter().any(|r| r.category == "device") {
        recommendations.push(SecurityRecommendation {
            id: "dynamic-device".to_string(),
            priority: "medium".to_string(),
            category: "device".to_string(),
            title: "Review Untrusted Devices".to_string(),
            description: format!("You have {} untrusted device(s). Review and trust devices you recognize.", untrusted.0),
            action_text: "Review Devices".to_string(),
            action_route: Some("/devices".to_string()),
            is_completed: false,
            created_at: Utc::now(),
        });
    }

    Ok(Json(recommendations))
}

/// Get MFA statistics (user-specific view)
async fn get_my_mfa_stats(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let user_id = Uuid::parse_str(&current_user.user_id)
        .map_err(|_| ApiError::bad_request("Invalid user ID"))?;

    let factors: Vec<(String, i64)> = sqlx::query_as(
        r#"
        SELECT factor_type, COUNT(*) as count
        FROM mfa_factors
        WHERE user_id = $1 AND verified = true
        GROUP BY factor_type
        "#
    )
    .bind(user_id)
    .fetch_all(state.db.pool())
    .await
    .map_err(|e| ApiError::internal_error(format!("Database error: {}", e)))?;

    let total_factors: i64 = factors.iter().map(|(_, c)| c).sum();

    let factors_by_type: Vec<FactorTypeStat> = factors
        .into_iter()
        .map(|(t, c)| FactorTypeStat {
            factor_type: t,
            count: c,
            percentage: if total_factors > 0 { (c as f64 / total_factors as f64) * 100.0 } else { 0.0 },
        })
        .collect();

    Ok(Json(serde_json::json!({
        "enabled": total_factors > 0,
        "totalFactors": total_factors,
        "factorsByType": factors_by_type,
        "backupCodesAvailable": total_factors > 0, // Would check backup_codes table
    })))
}

/// Get risk factors for current user
async fn get_my_risk_factors(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<RiskFactorsResponse>, ApiError> {
    let user_id = Uuid::parse_str(&current_user.user_id)
        .map_err(|_| ApiError::bad_request("Invalid user ID"))?;
    let tenant_id = Uuid::parse_str(&current_user.tenant_id)
        .map_err(|_| ApiError::bad_request("Invalid tenant ID"))?;

    // Get suspicious devices count
    let suspicious_devices: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*) FROM user_devices 
        WHERE user_id = $1 AND tenant_id = $2 AND is_trusted = false AND is_active = true
        "#
    )
    .bind(user_id)
    .bind(tenant_id)
    .fetch_one(state.db.pool())
    .await
    .map_err(|e| ApiError::internal_error(format!("Database error: {}", e)))?;

    // Get failed login attempts (last 24 hours)
    let failed_logins: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*) FROM audit_logs 
        WHERE user_id = $1 AND action = 'login' AND success = false 
        AND created_at > NOW() - INTERVAL '24 hours'
        "#
    )
    .bind(user_id)
    .fetch_one(state.db.pool())
    .await
    .map_err(|e| ApiError::internal_error(format!("Database error: {}", e)))?;

    // Get untrusted devices count
    let untrusted: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*) FROM user_devices 
        WHERE user_id = $1 AND tenant_id = $2 AND is_trusted = false AND is_active = true
        "#
    )
    .bind(user_id)
    .bind(tenant_id)
    .fetch_one(state.db.pool())
    .await
    .map_err(|e| ApiError::internal_error(format!("Database error: {}", e)))?;

    Ok(Json(RiskFactorsResponse {
        weak_passwords: 0, // Would need password strength analysis
        no_mfa_users: 0,   // Personal view, always 0
        suspicious_devices: suspicious_devices.0,
        failed_login_attempts: failed_logins.0,
        untrusted_devices: untrusted.0,
    }))
}
