//! Admin Custom Domains Routes
//!
//! API endpoints for managing custom domains (white-label authentication).
//! All routes are prefixed with `/api/v1/admin`.

use axum::{
    extract::{Path, State},
    routing::{delete, get, patch, post},
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};

use crate::audit::{AuditLogger, ResourceType};
use crate::domains::custom::{CustomDomain, CustomDomainStatus, DomainBranding, DomainValidator};
use crate::domains::custom_service::{CustomDomainConfig, CustomDomainService};
use crate::domains::SqlxCustomDomainRepository;
use crate::routes::ApiError;
use crate::state::{AppState, CurrentUser};

/// Create admin custom domain routes
///
/// Routes:
/// - GET    /custom-domains                   - List custom domains
/// - POST   /custom-domains                   - Add custom domain
/// - GET    /custom-domains/:id               - Get custom domain details
/// - DELETE /custom-domains/:id               - Remove custom domain
/// - POST   /custom-domains/:id/verify        - Verify DNS
/// - GET    /custom-domains/:id/status        - Check DNS/SSL status
/// - POST   /custom-domains/:id/regenerate-ssl - Regenerate SSL certificate
/// - PATCH  /custom-domains/:id/branding      - Update branding
/// - PATCH  /custom-domains/:id/ssl           - Update SSL settings
pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/custom-domains",
            get(list_custom_domains).post(create_custom_domain),
        )
        .route(
            "/custom-domains/:id",
            get(get_custom_domain).delete(delete_custom_domain),
        )
        .route("/custom-domains/:id/verify", post(verify_custom_domain))
        .route("/custom-domains/:id/status", get(get_custom_domain_status))
        .route("/custom-domains/:id/regenerate-ssl", post(regenerate_ssl))
        .route("/custom-domains/:id/branding", patch(update_branding))
        .route("/custom-domains/:id/ssl", patch(update_ssl_settings))
}

// ============ Request/Response Types ============

#[derive(Debug, Deserialize)]
struct CreateCustomDomainRequest {
    domain: String,
}

#[derive(Debug, Deserialize)]
struct UpdateBrandingRequest {
    #[serde(rename = "logoUrl")]
    logo_url: Option<String>,
    #[serde(rename = "primaryColor")]
    primary_color: Option<String>,
    #[serde(rename = "pageTitle")]
    page_title: Option<String>,
    #[serde(rename = "faviconUrl")]
    favicon_url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UpdateSslSettingsRequest {
    #[serde(rename = "autoSsl")]
    auto_ssl: Option<bool>,
    #[serde(rename = "forceHttps")]
    force_https: Option<bool>,
}

#[derive(Debug, Serialize)]
struct CustomDomainListResponse {
    data: Vec<CustomDomainResponse>,
}

#[derive(Debug, Serialize)]
struct CustomDomainResponse {
    id: String,
    #[serde(rename = "tenantId")]
    tenant_id: String,
    domain: String,
    status: String,
    #[serde(rename = "sslProvider")]
    ssl_provider: String,
    #[serde(rename = "autoSsl")]
    auto_ssl: bool,
    #[serde(rename = "forceHttps")]
    force_https: bool,
    #[serde(rename = "verifiedAt")]
    verified_at: Option<String>,
    #[serde(rename = "createdAt")]
    created_at: String,
    #[serde(rename = "updatedAt")]
    updated_at: String,
}

impl From<CustomDomain> for CustomDomainResponse {
    fn from(domain: CustomDomain) -> Self {
        Self {
            id: domain.id,
            tenant_id: domain.tenant_id,
            domain: domain.domain,
            status: domain.status.as_str().to_string(),
            ssl_provider: domain.ssl_provider.as_str().to_string(),
            auto_ssl: domain.auto_ssl,
            force_https: domain.force_https,
            verified_at: domain.verified_at.map(|d| d.to_rfc3339()),
            created_at: domain.created_at.to_rfc3339(),
            updated_at: domain.updated_at.to_rfc3339(),
        }
    }
}

#[derive(Debug, Serialize)]
struct CustomDomainDetailResponse {
    #[serde(flatten)]
    base: CustomDomainResponse,
    #[serde(rename = "verificationToken")]
    verification_token: String,
    #[serde(rename = "targetCname")]
    target_cname: Option<String>,
    #[serde(rename = "lastDnsCheckAt")]
    last_dns_check_at: Option<String>,
    #[serde(rename = "lastDnsCheckResult")]
    last_dns_check_result: Option<bool>,
    #[serde(rename = "lastDnsError")]
    last_dns_error: Option<String>,
    #[serde(rename = "certificateExpiresAt")]
    certificate_expires_at: Option<String>,
    branding: DomainBrandingResponse,
}

impl From<CustomDomain> for CustomDomainDetailResponse {
    fn from(domain: CustomDomain) -> Self {
        Self {
            base: domain.clone().into(),
            verification_token: domain.verification_token.clone(),
            target_cname: domain.target_cname.clone(),
            last_dns_check_at: domain.last_dns_check_at.map(|d| d.to_rfc3339()),
            last_dns_check_result: domain.last_dns_check_result,
            last_dns_error: domain.last_dns_error.clone(),
            certificate_expires_at: domain.certificate_expires_at.map(|d| d.to_rfc3339()),
            branding: DomainBrandingResponse {
                logo_url: domain.brand_logo_url.clone(),
                primary_color: domain.brand_primary_color.clone(),
                page_title: domain.brand_page_title.clone(),
                favicon_url: domain.brand_favicon_url.clone(),
            },
        }
    }
}

#[derive(Debug, Serialize)]
struct DomainBrandingResponse {
    #[serde(rename = "logoUrl")]
    logo_url: Option<String>,
    #[serde(rename = "primaryColor")]
    primary_color: Option<String>,
    #[serde(rename = "pageTitle")]
    page_title: Option<String>,
    #[serde(rename = "faviconUrl")]
    favicon_url: Option<String>,
}

#[derive(Debug, Serialize)]
struct DnsInstructionsResponse {
    domain: String,
    #[serde(rename = "recordType")]
    record_type: String,
    name: String,
    value: String,
    #[serde(rename = "verificationToken")]
    verification_token: String,
}

#[derive(Debug, Serialize)]
struct DnsStatusResponse {
    success: bool,
    #[serde(rename = "cnameRecord")]
    cname_record: Option<String>,
    #[serde(rename = "aRecords")]
    a_records: Vec<String>,
    #[serde(rename = "aaaaRecords")]
    aaaa_records: Vec<String>,
    error: Option<String>,
    #[serde(rename = "checkedAt")]
    checked_at: String,
}

impl From<crate::domains::custom::DnsVerificationResult> for DnsStatusResponse {
    fn from(result: crate::domains::custom::DnsVerificationResult) -> Self {
        Self {
            success: result.success,
            cname_record: result.cname_record,
            a_records: result.a_records,
            aaaa_records: result.aaaa_records,
            error: result.error,
            checked_at: result.checked_at.to_rfc3339(),
        }
    }
}

#[derive(Debug, Serialize)]
struct SslStatusResponse {
    provider: String,
    #[serde(rename = "autoSsl")]
    auto_ssl: bool,
    #[serde(rename = "forceHttps")]
    force_https: bool,
    #[serde(rename = "certificateExpiresAt")]
    certificate_expires_at: Option<String>,
    #[serde(rename = "daysUntilExpiry")]
    days_until_expiry: Option<u32>,
    #[serde(rename = "needsRenewal")]
    needs_renewal: bool,
}

#[derive(Debug, Serialize)]
struct CustomDomainStatusResponse {
    #[serde(flatten)]
    domain: CustomDomainDetailResponse,
    dns: DnsInstructionsResponse,
}

// ============ Service Helper ============

fn create_service(
    state: &AppState,
) -> anyhow::Result<CustomDomainService<SqlxCustomDomainRepository>> {
    let config = CustomDomainConfig {
        base_domain: state.config.custom_domains.base_domain.clone(),
        cert_storage_path: state.config.custom_domains.cert_storage_path.clone(),
        auto_verify_dns: state.config.custom_domains.auto_verify_dns,
        enable_ssl: state.config.custom_domains.enable_ssl,
    };

    let repository = SqlxCustomDomainRepository::new(std::sync::Arc::new(state.db.pool().clone()));

    // Create runtime for async initialization (in production, this should be handled differently)
    let runtime = tokio::runtime::Handle::current();
    let dns_verifier = runtime.block_on(crate::domains::custom::CustomDomainDnsVerifier::new())?;

    Ok(CustomDomainService {
        repository,
        dns_verifier,
        config,
    })
}

// ============ Handlers ============

/// List all custom domains for the tenant
async fn list_custom_domains(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<CustomDomainListResponse>, ApiError> {
    // Set tenant context
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let service = create_service(&state).map_err(|_| ApiError::Internal)?;

    let domains = service
        .list_domains(&current_user.tenant_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to list custom domains: {}", e);
            ApiError::Internal
        })?;

    Ok(Json(CustomDomainListResponse {
        data: domains.into_iter().map(Into::into).collect(),
    }))
}

/// Create a new custom domain
async fn create_custom_domain(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<CreateCustomDomainRequest>,
) -> Result<Json<CustomDomainResponse>, ApiError> {
    // Set tenant context
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    // Validate domain format
    let sanitized = DomainValidator::sanitize(&req.domain);
    if let Err(e) = DomainValidator::validate_format(&sanitized) {
        return Err(ApiError::Validation(e.to_string()));
    }

    let service = create_service(&state).map_err(|_| ApiError::Internal)?;

    let domain = service
        .create_domain(
            &current_user.tenant_id,
            &req.domain,
            Some(&current_user.user_id),
        )
        .await
        .map_err(|e| {
            tracing::error!("Failed to create custom domain: {}", e);
            if e.to_string().contains("already registered") {
                ApiError::Conflict(e.to_string())
            } else {
                ApiError::Internal
            }
        })?;

    // Log the action
    let audit = AuditLogger::new(state.db.clone());
    audit.log(
        &current_user.tenant_id,
        crate::audit::AuditAction::DomainCreated,
        ResourceType::Domain,
        &domain.id,
        Some(current_user.user_id.clone()),
        None,
        None,
        true,
        None,
        Some(serde_json::json!({
            "domain_id": domain.id,
            "domain": domain.domain,
            "domain_type": "custom",
        })),
    );

    Ok(Json(domain.into()))
}

/// Get a custom domain by ID
async fn get_custom_domain(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(id): Path<String>,
) -> Result<Json<CustomDomainDetailResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let service = create_service(&state).map_err(|_| ApiError::Internal)?;

    let domain = service
        .get_domain(&current_user.tenant_id, &id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get custom domain: {}", e);
            ApiError::Internal
        })?
        .ok_or(ApiError::NotFound)?;

    Ok(Json(domain.into()))
}

/// Delete a custom domain
async fn delete_custom_domain(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let service = create_service(&state).map_err(|_| ApiError::Internal)?;

    // Get domain info for audit log before deleting
    let domain_info = service
        .get_domain(&current_user.tenant_id, &id)
        .await
        .map_err(|_| ApiError::Internal)?;

    service
        .delete_domain(&current_user.tenant_id, &id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to delete custom domain: {}", e);
            ApiError::Internal
        })?;

    // Log the action
    let audit = AuditLogger::new(state.db.clone());
    audit.log(
        &current_user.tenant_id,
        crate::audit::AuditAction::DomainDeleted,
        ResourceType::Domain,
        &id,
        Some(current_user.user_id.clone()),
        None,
        None,
        true,
        None,
        Some(serde_json::json!({
            "domain_id": id,
            "domain": domain_info.map(|d| d.domain).unwrap_or_default(),
            "domain_type": "custom",
        })),
    );

    Ok(Json(serde_json::json!({
        "message": "Custom domain deleted successfully"
    })))
}

/// Verify DNS for a custom domain
async fn verify_custom_domain(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(id): Path<String>,
) -> Result<Json<DnsStatusResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let service = create_service(&state).map_err(|_| ApiError::Internal)?;

    let result = service
        .verify_dns(&current_user.tenant_id, &id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to verify custom domain: {}", e);
            ApiError::Internal
        })?;

    // Log the action
    let audit = AuditLogger::new(state.db.clone());
    let action = if result.success {
        crate::audit::AuditAction::DomainVerified
    } else {
        crate::audit::AuditAction::DomainVerificationFailed
    };
    audit.log(
        &current_user.tenant_id,
        action,
        ResourceType::Domain,
        &id,
        Some(current_user.user_id.clone()),
        None,
        None,
        result.success,
        if result.success {
            None
        } else {
            result.error.clone()
        },
        Some(serde_json::json!({
            "domain_id": id,
            "domain_type": "custom",
            "verification_method": "dns",
        })),
    );

    Ok(Json(result.into()))
}

/// Get custom domain status (DNS and SSL)
async fn get_custom_domain_status(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let service = create_service(&state).map_err(|_| ApiError::Internal)?;

    // Get domain info
    let domain = service
        .get_domain(&current_user.tenant_id, &id)
        .await
        .map_err(|_| ApiError::Internal)?
        .ok_or(ApiError::NotFound)?;

    // Get SSL status
    let ssl_status = service
        .get_ssl_status(&current_user.tenant_id, &id)
        .await
        .map_err(|_| ApiError::Internal)?;

    // Get current DNS status
    let dns_status = service
        .check_dns_status(&domain.domain)
        .await
        .map_err(|_| ApiError::Internal)?;

    Ok(Json(serde_json::json!({
        "domain": CustomDomainDetailResponse::from(domain),
        "ssl": ssl_status,
        "dns": DnsStatusResponse::from(dns_status),
    })))
}

/// Regenerate SSL certificate
async fn regenerate_ssl(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(id): Path<String>,
) -> Result<Json<CustomDomainResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let service = create_service(&state).map_err(|_| ApiError::Internal)?;

    let domain = service
        .regenerate_ssl(&current_user.tenant_id, &id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to regenerate SSL: {}", e);
            ApiError::Internal
        })?;

    // Log the action
    let audit = AuditLogger::new(state.db.clone());
    audit.log(
        &current_user.tenant_id,
        crate::audit::AuditAction::DomainUpdated,
        ResourceType::Domain,
        &id,
        Some(current_user.user_id.clone()),
        None,
        None,
        true,
        None,
        Some(serde_json::json!({
            "domain_id": id,
            "update_type": "ssl_regenerate",
        })),
    );

    Ok(Json(domain.into()))
}

/// Update domain branding
async fn update_branding(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(id): Path<String>,
    Json(req): Json<UpdateBrandingRequest>,
) -> Result<Json<CustomDomainResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let service = create_service(&state).map_err(|_| ApiError::Internal)?;

    let branding = DomainBranding {
        logo_url: req.logo_url,
        primary_color: req.primary_color,
        page_title: req.page_title,
        favicon_url: req.favicon_url,
    };

    let domain = service
        .update_branding(&current_user.tenant_id, &id, branding)
        .await
        .map_err(|e| {
            tracing::error!("Failed to update branding: {}", e);
            ApiError::Internal
        })?;

    Ok(Json(domain.into()))
}

/// Update SSL settings
async fn update_ssl_settings(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(id): Path<String>,
    Json(req): Json<UpdateSslSettingsRequest>,
) -> Result<Json<CustomDomainResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let service = create_service(&state).map_err(|_| ApiError::Internal)?;

    let auto_ssl = req.auto_ssl.unwrap_or(true);
    let force_https = req.force_https.unwrap_or(true);

    let domain = service
        .update_ssl_settings(&current_user.tenant_id, &id, auto_ssl, force_https)
        .await
        .map_err(|e| {
            tracing::error!("Failed to update SSL settings: {}", e);
            ApiError::Internal
        })?;

    Ok(Json(domain.into()))
}
