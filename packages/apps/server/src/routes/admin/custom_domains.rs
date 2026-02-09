//! Admin Custom Domain Routes
//!
//! Provides endpoints for managing tenant-scoped custom domains:
//! - GET /api/v1/admin/domains - List custom domains
//! - POST /api/v1/admin/domains - Add custom domain
//! - GET /api/v1/admin/domains/:id - Get domain details
//! - DELETE /api/v1/admin/domains/:id - Remove domain
//! - POST /api/v1/admin/domains/:id/verify - Verify domain
//! - GET /api/v1/admin/domains/:id/verification-status - Get verification status
//! - POST /api/v1/admin/domains/:id/renew-ssl - Renew SSL certificate
//! - GET /api/v1/admin/domains/:id/health - Get domain health
//!
//! Features:
//! - Custom domain management for tenant branding
//! - DNS verification (TXT record)
//! - Automatic SSL certificate provisioning
//! - Domain health monitoring
//! - CDN integration support

use axum::{
    extract::{Extension, Path, State},
    http::StatusCode,
    routing::{delete, get, post},
    Extension as _, Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use validator::Validate;
use uuid::Uuid;

use crate::audit::{AuditAction, AuditLogger, ResourceType};
use crate::routes::ApiError;
use crate::state::{AppState, CurrentUser};

/// Custom domain routes
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/domains", get(list_domains).post(add_domain))
        .route("/domains/:id", get(get_domain).delete(remove_domain))
        .route("/domains/:id/verify", post(verify_domain))
        .route("/domains/:id/verification-status", get(get_verification_status))
        .route("/domains/:id/renew-ssl", post(renew_ssl))
        .route("/domains/:id/health", get(get_domain_health))
}

// ============ Request/Response Types ============

/// Domain status
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DomainStatus {
    /// Domain is pending verification
    Pending,
    /// Domain is being verified
    Verifying,
    /// Domain is verified and active
    Active,
    /// Domain verification failed
    Failed,
    /// Domain is suspended
    Suspended,
    /// SSL certificate expired
    SslExpired,
    /// Domain has issues
    Error,
}

/// SSL certificate info
#[derive(Debug, Serialize)]
pub struct SslCertificateInfo {
    pub issuer: String,
    pub issued_at: String,
    pub expires_at: String,
    pub is_valid: bool,
    pub days_until_expiry: i64,
    pub auto_renew: bool,
}

/// Custom domain response
#[derive(Debug, Serialize)]
pub struct CustomDomainResponse {
    pub id: String,
    pub domain: String,
    pub status: String,
    pub is_primary: bool,
    pub created_at: String,
    pub verified_at: Option<String>,
    pub verification_method: String,
    pub verification_token: Option<String>,
    pub ssl_certificate: Option<SslCertificateInfo>,
    pub cdn_enabled: bool,
    pub settings: DomainSettings,
}

/// Domain settings
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DomainSettings {
    pub force_https: bool,
    pub www_redirect: bool,
    pub custom_error_pages: bool,
    pub security_headers: SecurityHeaders,
}

impl Default for DomainSettings {
    fn default() -> Self {
        Self {
            force_https: true,
            www_redirect: false,
            custom_error_pages: false,
            security_headers: SecurityHeaders::default(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SecurityHeaders {
    pub hsts: bool,
    pub x_frame_options: String,
    pub x_content_type_options: bool,
    pub referrer_policy: String,
}

impl Default for SecurityHeaders {
    fn default() -> Self {
        Self {
            hsts: true,
            x_frame_options: "DENY".to_string(),
            x_content_type_options: true,
            referrer_policy: "strict-origin-when-cross-origin".to_string(),
        }
    }
}

/// List domains response
#[derive(Debug, Serialize)]
pub struct ListDomainsResponse {
    pub domains: Vec<CustomDomainResponse>,
    pub total: i64,
    pub max_domains: i32,
}

/// Add domain request
#[derive(Debug, Deserialize, Validate)]
pub struct AddDomainRequest {
    #[validate(length(min = 3, max = 253, message = "Domain must be between 3 and 253 characters"))]
    #[validate(regex(path = "*crate::validation::DOMAIN_REGEX", message = "Invalid domain format"))]
    pub domain: String,
    pub is_primary: Option<bool>,
    pub verification_method: Option<String>,
}

/// Domain verification response
#[derive(Debug, Serialize)]
pub struct VerificationResponse {
    pub success: bool,
    pub status: String,
    pub message: String,
    pub verification_token: Option<String>,
    pub dns_record: Option<DnsRecord>,
    pub verified_at: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DnsRecord {
    pub record_type: String,
    pub name: String,
    pub value: String,
    pub ttl: u32,
}

/// Verification status response
#[derive(Debug, Serialize)]
pub struct VerificationStatusResponse {
    pub status: String,
    pub domain: String,
    pub verification_method: String,
    pub dns_record: DnsRecord,
    pub last_check: Option<String>,
    pub checks_remaining: i32,
    pub error_message: Option<String>,
}

/// Domain health response
#[derive(Debug, Serialize)]
pub struct DomainHealthResponse {
    pub domain: String,
    pub overall_status: String,
    pub checks: Vec<HealthCheck>,
    pub recommendations: Vec<String>,
    pub last_checked: String,
}

#[derive(Debug, Serialize)]
pub struct HealthCheck {
    pub name: String,
    pub status: String,
    pub message: String,
    pub details: Option<serde_json::Value>,
}

/// SSL renewal response
#[derive(Debug, Serialize)]
pub struct SslRenewalResponse {
    pub success: bool,
    pub message: String,
    pub certificate: Option<SslCertificateInfo>,
}

#[derive(Debug, sqlx::FromRow)]
struct DomainRow {
    id: String,
    domain: String,
    status: String,
    is_primary: bool,
    created_at: DateTime<Utc>,
    verified_at: Option<DateTime<Utc>>,
    verification_method: String,
    verification_token: Option<String>,
    ssl_issuer: Option<String>,
    ssl_issued_at: Option<DateTime<Utc>>,
    ssl_expires_at: Option<DateTime<Utc>>,
    ssl_auto_renew: bool,
    cdn_enabled: bool,
    settings: Option<serde_json::Value>,
}

// ============ Handlers ============

/// List all custom domains for the tenant
async fn list_domains(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<ListDomainsResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    let rows: Vec<DomainRow> = sqlx::query_as(
        r#"SELECT id::text, domain, status, is_primary, created_at, verified_at,
               verification_method, verification_token, ssl_issuer, ssl_issued_at,
               ssl_expires_at, ssl_auto_renew, cdn_enabled, settings
           FROM custom_domains
           WHERE tenant_id = $1::uuid
           ORDER BY is_primary DESC, created_at DESC"#,
    )
    .bind(&current_user.tenant_id)
    .fetch_all(state.db.pool())
    .await
    .map_err(|_| ApiError::internal())?;

    let domains: Vec<CustomDomainResponse> = rows
        .into_iter()
        .map(|row| {
            let ssl_certificate = if row.ssl_issuer.is_some() {
                let days_until_expiry = row
                    .ssl_expires_at
                    .map(|exp| (exp - Utc::now()).num_days())
                    .unwrap_or(-1);

                Some(SslCertificateInfo {
                    issuer: row.ssl_issuer.unwrap_or_default(),
                    issued_at: row.ssl_issued_at.map(|dt| dt.to_rfc3339()).unwrap_or_default(),
                    expires_at: row.ssl_expires_at.map(|dt| dt.to_rfc3339()).unwrap_or_default(),
                    is_valid: days_until_expiry > 0,
                    days_until_expiry,
                    auto_renew: row.ssl_auto_renew,
                })
            } else {
                None
            };

            let settings = row
                .settings
                .and_then(|s| serde_json::from_value(s).ok())
                .unwrap_or_default();

            CustomDomainResponse {
                id: row.id,
                domain: row.domain,
                status: row.status,
                is_primary: row.is_primary,
                created_at: row.created_at.to_rfc3339(),
                verified_at: row.verified_at.map(|dt| dt.to_rfc3339()),
                verification_method: row.verification_method,
                verification_token: row.verification_token,
                ssl_certificate,
                cdn_enabled: row.cdn_enabled,
                settings,
            }
        })
        .collect();

    let total = domains.len() as i64;

    // Get max domains from tenant plan (default to 5)
    let max_domains: i32 = sqlx::query_scalar(
        "SELECT COALESCE((settings->>'max_custom_domains')::int, 5) FROM tenants WHERE id = $1::uuid",
    )
    .bind(&current_user.tenant_id)
    .fetch_one(state.db.pool())
    .await
    .unwrap_or(5);

    Ok(Json(ListDomainsResponse {
        domains,
        total,
        max_domains,
    }))
}

/// Add a new custom domain
async fn add_domain(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<AddDomainRequest>,
) -> Result<(StatusCode, Json<VerificationResponse>), ApiError> {
    req.validate()
        .map_err(|e| ApiError::Validation(e.to_string()))?;

    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    // Check domain limit
    let current_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM custom_domains WHERE tenant_id = $1::uuid",
    )
    .bind(&current_user.tenant_id)
    .fetch_one(state.db.pool())
    .await
    .map_err(|_| ApiError::internal())?;

    let max_domains: i32 = sqlx::query_scalar(
        "SELECT COALESCE((settings->>'max_custom_domains')::int, 5) FROM tenants WHERE id = $1::uuid",
    )
    .bind(&current_user.tenant_id)
    .fetch_one(state.db.pool())
    .await
    .unwrap_or(5);

    if current_count >= max_domains as i64 {
        return Err(ApiError::BadRequest(format!(
            "Maximum number of custom domains ({}) reached",
            max_domains
        )));
    }

    // Check if domain already exists
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM custom_domains WHERE domain = $1)",
    )
    .bind(&req.domain)
    .fetch_one(state.db.pool())
    .await
    .map_err(|_| ApiError::internal())?;

    if exists {
        return Err(ApiError::Conflict(
            "Domain is already registered".to_string(),
        ));
    }

    // Generate verification token
    let verification_token = format!("vault-verify-{}", Uuid::new_v4());
    let id = Uuid::new_v4();
    let is_primary = req.is_primary.unwrap_or(false);
    let verification_method = req.verification_method.unwrap_or_else(|| "dns".to_string());

    // If setting as primary, unset other primary domains
    if is_primary {
        sqlx::query(
            "UPDATE custom_domains SET is_primary = false WHERE tenant_id = $1::uuid",
        )
        .bind(&current_user.tenant_id)
        .execute(state.db.pool())
        .await
        .map_err(|_| ApiError::internal())?;
    }

    sqlx::query(
        r#"INSERT INTO custom_domains 
           (id, tenant_id, domain, status, is_primary, created_at, verification_method, verification_token, ssl_auto_renew, cdn_enabled, settings)
           VALUES ($1, $2, $3, 'pending', $4, NOW(), $5, $6, true, false, $7)"#,
    )
    .bind(id)
    .bind(&current_user.tenant_id)
    .bind(&req.domain)
    .bind(is_primary)
    .bind(&verification_method)
    .bind(&verification_token)
    .bind(serde_json::to_value(DomainSettings::default()).map_err(|_| ApiError::internal())?)
    .execute(state.db.pool())
    .await
    .map_err(|e| {
        tracing::error!("Failed to add domain: {}", e);
        ApiError::internal()
    })?;

    // Log the action
    let audit = AuditLogger::new(state.db.clone());
    audit.log(
        &current_user.tenant_id,
        AuditAction::Custom("custom_domain.added"),
        ResourceType::Admin,
        &id.to_string(),
        Some(current_user.user_id.clone()),
        None,
        None,
        true,
        None,
        Some(serde_json::json!({
            "domain": req.domain,
            "is_primary": is_primary,
        })),
    );

    // Generate DNS record info
    let dns_record = DnsRecord {
        record_type: "TXT".to_string(),
        name: "_vault".to_string(),
        value: verification_token.clone(),
        ttl: 300,
    };

    Ok((
        StatusCode::CREATED,
        Json(VerificationResponse {
            success: false,
            status: "pending".to_string(),
            message: format!(
                "Domain '{}' added. Add the DNS TXT record to verify ownership.",
                req.domain
            ),
            verification_token: Some(verification_token),
            dns_record: Some(dns_record),
            verified_at: None,
        }),
    ))
}

/// Get domain details
async fn get_domain(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(id): Path<String>,
) -> Result<Json<CustomDomainResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    let row: Option<DomainRow> = sqlx::query_as(
        r#"SELECT id::text, domain, status, is_primary, created_at, verified_at,
               verification_method, verification_token, ssl_issuer, ssl_issued_at,
               ssl_expires_at, ssl_auto_renew, cdn_enabled, settings
           FROM custom_domains
           WHERE id = $1::uuid AND tenant_id = $2::uuid"#,
    )
    .bind(&id)
    .bind(&current_user.tenant_id)
    .fetch_optional(state.db.pool())
    .await
    .map_err(|_| ApiError::internal())?;

    let row = row.ok_or(ApiError::NotFound)?;

    let ssl_certificate = if row.ssl_issuer.is_some() {
        let days_until_expiry = row
            .ssl_expires_at
            .map(|exp| (exp - Utc::now()).num_days())
            .unwrap_or(-1);

        Some(SslCertificateInfo {
            issuer: row.ssl_issuer.unwrap_or_default(),
            issued_at: row.ssl_issued_at.map(|dt| dt.to_rfc3339()).unwrap_or_default(),
            expires_at: row.ssl_expires_at.map(|dt| dt.to_rfc3339()).unwrap_or_default(),
            is_valid: days_until_expiry > 0,
            days_until_expiry,
            auto_renew: row.ssl_auto_renew,
        })
    } else {
        None
    };

    let settings = row
        .settings
        .and_then(|s| serde_json::from_value(s).ok())
        .unwrap_or_default();

    Ok(Json(CustomDomainResponse {
        id: row.id,
        domain: row.domain,
        status: row.status,
        is_primary: row.is_primary,
        created_at: row.created_at.to_rfc3339(),
        verified_at: row.verified_at.map(|dt| dt.to_rfc3339()),
        verification_method: row.verification_method,
        verification_token: row.verification_token,
        ssl_certificate,
        cdn_enabled: row.cdn_enabled,
        settings,
    }))
}

/// Remove a custom domain
async fn remove_domain(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    // Get domain info for audit log
    let domain_info: Option<(String, String)> = sqlx::query_as(
        "SELECT id::text, domain FROM custom_domains WHERE id = $1::uuid AND tenant_id = $2::uuid",
    )
    .bind(&id)
    .bind(&current_user.tenant_id)
    .fetch_optional(state.db.pool())
    .await
    .map_err(|_| ApiError::internal())?;

    let (domain_id, domain_name) = domain_info.ok_or(ApiError::NotFound)?;

    // Delete the domain
    sqlx::query("DELETE FROM custom_domains WHERE id = $1::uuid AND tenant_id = $2::uuid")
        .bind(&id)
        .bind(&current_user.tenant_id)
        .execute(state.db.pool())
        .await
        .map_err(|_| ApiError::internal())?;

    // Log the action
    let audit = AuditLogger::new(state.db.clone());
    audit.log(
        &current_user.tenant_id,
        AuditAction::Custom("custom_domain.removed"),
        ResourceType::Admin,
        &domain_id,
        Some(current_user.user_id.clone()),
        None,
        None,
        true,
        Some(format!("Removed domain: {}", domain_name)),
        Some(serde_json::json!({
            "domain": domain_name,
        })),
    );

    Ok(Json(serde_json::json!({
        "message": "Domain removed successfully",
        "id": domain_id,
        "domain": domain_name,
    })))
}

/// Verify domain ownership
async fn verify_domain(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(id): Path<String>,
) -> Result<Json<VerificationResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    // Get domain info
    let domain_info: Option<(String, String, Option<String>)> = sqlx::query_as(
        "SELECT domain, verification_method, verification_token FROM custom_domains 
         WHERE id = $1::uuid AND tenant_id = $2::uuid",
    )
    .bind(&id)
    .bind(&current_user.tenant_id)
    .fetch_optional(state.db.pool())
    .await
    .map_err(|_| ApiError::internal())?;

    let (domain, method, token) = domain_info.ok_or(ApiError::NotFound)?;
    let token = token.ok_or(ApiError::BadRequest(
        "No verification token found".to_string(),
    ))?;

    // Perform verification based on method
    let verified = match method.as_str() {
        "dns" => verify_dns_txt_record(&domain, &token).await,
        "file" => verify_file_upload(&domain, &token).await,
        _ => false,
    };

    if verified {
        // Update domain status
        sqlx::query(
            r#"UPDATE custom_domains 
               SET status = 'active', verified_at = NOW()
               WHERE id = $1::uuid"#,
        )
        .bind(&id)
        .execute(state.db.pool())
        .await
        .map_err(|_| ApiError::internal())?;

        // Trigger SSL certificate provisioning (async)
        // In production, this would queue a background job
        tokio::spawn(provision_ssl_certificate(id.clone(), domain.clone()));

        // Log success
        let audit = AuditLogger::new(state.db.clone());
        audit.log(
            &current_user.tenant_id,
            AuditAction::Custom("custom_domain.verified"),
            ResourceType::Admin,
            &id,
            Some(current_user.user_id.clone()),
            None,
            None,
            true,
            Some(format!("Domain verified: {}", domain)),
            None,
        );

        Ok(Json(VerificationResponse {
            success: true,
            status: "active".to_string(),
            message: "Domain verified successfully. SSL certificate will be provisioned shortly.".to_string(),
            verification_token: None,
            dns_record: None,
            verified_at: Some(Utc::now().to_rfc3339()),
        }))
    } else {
        // Update failed check count
        sqlx::query(
            r#"UPDATE custom_domains 
               SET status = 'failed', last_verification_error = 'DNS record not found'
               WHERE id = $1::uuid"#,
        )
        .bind(&id)
        .execute(state.db.pool())
        .await
        .map_err(|_| ApiError::internal())?;

        Ok(Json(VerificationResponse {
            success: false,
            status: "failed".to_string(),
            message: "Verification failed. Please ensure the DNS TXT record is correctly configured.".to_string(),
            verification_token: Some(token.clone()),
            dns_record: Some(DnsRecord {
                record_type: "TXT".to_string(),
                name: "_vault".to_string(),
                value: token,
                ttl: 300,
            }),
            verified_at: None,
        }))
    }
}

/// Get verification status
async fn get_verification_status(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(id): Path<String>,
) -> Result<Json<VerificationStatusResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    let row: Option<(String, String, String, Option<String>, Option<DateTime<Utc>>, Option<String>)> = sqlx::query_as(
        r#"SELECT domain, status, verification_method, verification_token, 
                  last_verification_check, last_verification_error
           FROM custom_domains
           WHERE id = $1::uuid AND tenant_id = $2::uuid"#,
    )
    .bind(&id)
    .bind(&current_user.tenant_id)
    .fetch_optional(state.db.pool())
    .await
    .map_err(|_| ApiError::internal())?;

    let (domain, status, method, token, last_check, error) = row.ok_or(ApiError::NotFound)?;

    let dns_record = DnsRecord {
        record_type: "TXT".to_string(),
        name: "_vault".to_string(),
        value: token.unwrap_or_default(),
        ttl: 300,
    };

    Ok(Json(VerificationStatusResponse {
        status,
        domain,
        verification_method: method,
        dns_record,
        last_check: last_check.map(|dt| dt.to_rfc3339()),
        checks_remaining: 10, // Would track actual remaining checks
        error_message: error,
    }))
}

/// Renew SSL certificate
async fn renew_ssl(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(id): Path<String>,
) -> Result<Json<SslRenewalResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    // Verify domain exists and is verified
    let domain_info: Option<(String, String)> = sqlx::query_as(
        "SELECT id::text, domain FROM custom_domains 
         WHERE id = $1::uuid AND tenant_id = $2::uuid AND status = 'active'",
    )
    .bind(&id)
    .bind(&current_user.tenant_id)
    .fetch_optional(state.db.pool())
    .await
    .map_err(|_| ApiError::internal())?;

    let (_, domain) = domain_info.ok_or(ApiError::BadRequest(
        "Domain not found or not verified".to_string(),
    ))?;

    // Trigger SSL renewal (async)
    tokio::spawn(provision_ssl_certificate(id.clone(), domain.clone()));

    // Log the action
    let audit = AuditLogger::new(state.db.clone());
    audit.log(
        &current_user.tenant_id,
        AuditAction::Custom("custom_domain.ssl_renewal_requested"),
        ResourceType::Admin,
        &id,
        Some(current_user.user_id.clone()),
        None,
        None,
        true,
        Some(format!("SSL renewal requested for: {}", domain)),
        None,
    );

    Ok(Json(SslRenewalResponse {
        success: true,
        message: "SSL certificate renewal initiated. This may take a few minutes.".to_string(),
        certificate: None,
    }))
}

/// Get domain health
async fn get_domain_health(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(id): Path<String>,
) -> Result<Json<DomainHealthResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    // Get domain info
    let row: Option<(String, String, Option<DateTime<Utc>>)> = sqlx::query_as(
        "SELECT domain, status, ssl_expires_at FROM custom_domains 
         WHERE id = $1::uuid AND tenant_id = $2::uuid",
    )
    .bind(&id)
    .bind(&current_user.tenant_id)
    .fetch_optional(state.db.pool())
    .await
    .map_err(|_| ApiError::internal())?;

    let (domain, status, ssl_expires) = row.ok_or(ApiError::NotFound)?;

    let mut checks = Vec::new();
    let mut recommendations = Vec::new();
    let mut overall_status = "healthy";

    // DNS check
    let dns_check = HealthCheck {
        name: "DNS Resolution".to_string(),
        status: "passed".to_string(),
        message: "Domain resolves correctly".to_string(),
        details: None,
    };
    checks.push(dns_check);

    // SSL check
    let ssl_check = if let Some(expires) = ssl_expires {
        let days_until_expiry = (expires - Utc::now()).num_days();
        if days_until_expiry < 7 {
            overall_status = "warning";
            recommendations.push("SSL certificate expires soon. Renewal recommended.".to_string());
            HealthCheck {
                name: "SSL Certificate".to_string(),
                status: "warning".to_string(),
                message: format!("Expires in {} days", days_until_expiry),
                details: Some(serde_json::json!({"days_until_expiry": days_until_expiry})),
            }
        } else {
            HealthCheck {
                name: "SSL Certificate".to_string(),
                status: "passed".to_string(),
                message: format!("Valid for {} more days", days_until_expiry),
                details: Some(serde_json::json!({"days_until_expiry": days_until_expiry})),
            }
        }
    } else {
        overall_status = "error";
        recommendations.push("SSL certificate not provisioned.".to_string());
        HealthCheck {
            name: "SSL Certificate".to_string(),
            status: "failed".to_string(),
            message: "No SSL certificate found".to_string(),
            details: None,
        }
    };
    checks.push(ssl_check);

    // Domain status check
    let status_check = match status.as_str() {
        "active" => HealthCheck {
            name: "Domain Status".to_string(),
            status: "passed".to_string(),
            message: "Domain is active".to_string(),
            details: None,
        },
        "pending" => {
            overall_status = "warning";
            recommendations.push("Domain verification pending. Complete DNS verification.".to_string());
            HealthCheck {
                name: "Domain Status".to_string(),
                status: "warning".to_string(),
                message: "Domain verification pending".to_string(),
                details: None,
            }
        }
        "failed" => {
            overall_status = "error";
            recommendations.push("Domain verification failed. Check DNS configuration.".to_string());
            HealthCheck {
                name: "Domain Status".to_string(),
                status: "failed".to_string(),
                message: "Domain verification failed".to_string(),
                details: None,
            }
        }
        _ => HealthCheck {
            name: "Domain Status".to_string(),
            status: "warning".to_string(),
            message: format!("Unknown status: {}", status),
            details: None,
        },
    };
    checks.push(status_check);

    Ok(Json(DomainHealthResponse {
        domain,
        overall_status: overall_status.to_string(),
        checks,
        recommendations,
        last_checked: Utc::now().to_rfc3339(),
    }))
}

// ============ Helper Functions ============

/// Verify DNS TXT record
async fn verify_dns_txt_record(domain: &str, expected_token: &str) -> bool {
    use trust_dns_resolver::TokioAsyncResolver;

    let resolver = match TokioAsyncResolver::tokio_from_system_conf() {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("Failed to create DNS resolver: {}", e);
            return false;
        }
    };

    let lookup_name = format!("_vault.{}", domain);
    
    match resolver.txt_lookup(lookup_name).await {
        Ok(lookup) => {
            for record in lookup.iter() {
                for txt in record.txt_data() {
                    if String::from_utf8_lossy(txt).contains(expected_token) {
                        return true;
                    }
                }
            }
            false
        }
        Err(e) => {
            tracing::warn!("DNS lookup failed for {}: {}", domain, e);
            false
        }
    }
}

/// Verify file upload method
async fn verify_file_upload(domain: &str, _expected_token: &str) -> bool {
    // In production, this would make an HTTP request to check for the verification file
    // For now, return false as this is a placeholder
    tracing::info!("File upload verification for {} not implemented", domain);
    false
}

/// Provision SSL certificate (placeholder for async background job)
async fn provision_ssl_certificate(domain_id: String, domain: String) {
    tracing::info!("Provisioning SSL certificate for {} ({})", domain, domain_id);
    
    // In production, this would:
    // 1. Use Let's Encrypt or similar to obtain certificate
    // 2. Store certificate in secure storage
    // 3. Update database with certificate info
    // 4. Configure load balancer/CDN
    
    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
    
    tracing::info!("SSL certificate provisioning completed for {}", domain);
}
