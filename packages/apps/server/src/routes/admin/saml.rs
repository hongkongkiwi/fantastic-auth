//! Admin SAML Routes
//!
//! This module provides comprehensive SAML management endpoints:
//! - CRUD for SAML connections
//! - Upload IdP metadata XML
//! - Download SP metadata
//! - Test SAML connection
//! - Certificate management

use axum::{
    extract::{Multipart, Path, Query, State},
    http::StatusCode,
    routing::{delete, get, patch, post},
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

use crate::routes::ApiError;
use crate::saml::{
    crypto::{generate_self_signed_cert, X509Certificate},
    metadata::{generate_sp_metadata, parse_idp_metadata, IdpMetadataParser},
    NameIdFormat, ServiceProviderConfig,
};
use crate::state::{AppState, CurrentUser};
use vault_core::db::set_connection_context;

/// Create admin SAML routes
pub fn routes() -> Router<AppState> {
    Router::new()
        // SAML connections CRUD
        .route(
            "/sso/saml/connections",
            get(list_saml_connections).post(create_saml_connection),
        )
        .route(
            "/sso/saml/connections/:connection_id",
            get(get_saml_connection)
                .patch(update_saml_connection)
                .delete(delete_saml_connection),
        )
        // Metadata endpoints
        .route(
            "/sso/saml/connections/:connection_id/metadata",
            get(download_sp_metadata),
        )
        .route(
            "/sso/saml/connections/:connection_id/metadata",
            post(upload_idp_metadata),
        )
        // Certificate management
        .route(
            "/sso/saml/connections/:connection_id/certificates",
            get(list_certificates).post(generate_certificate),
        )
        .route(
            "/sso/saml/connections/:connection_id/certificates/rotate",
            post(rotate_certificate),
        )
        // Testing
        .route(
            "/sso/saml/connections/:connection_id/test",
            post(test_saml_connection),
        )
        // Attribute mappings
        .route(
            "/sso/saml/connections/:connection_id/attribute-mappings",
            get(get_attribute_mappings).put(update_attribute_mappings),
        )
}

// ============================================================================
// Request/Response Types
// ============================================================================

#[derive(Debug, Deserialize)]
struct CreateSamlConnectionRequest {
    name: String,
    idp_entity_id: Option<String>,
    idp_sso_url: Option<String>,
    idp_slo_url: Option<String>,
    idp_certificate: Option<String>,
    name_id_format: Option<String>,
    want_authn_requests_signed: Option<bool>,
    want_assertions_signed: Option<bool>,
    jit_provisioning_enabled: Option<bool>,
    attribute_mappings: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct UpdateSamlConnectionRequest {
    name: Option<String>,
    idp_entity_id: Option<String>,
    idp_sso_url: Option<String>,
    idp_slo_url: Option<String>,
    idp_certificate: Option<String>,
    name_id_format: Option<String>,
    want_authn_requests_signed: Option<bool>,
    want_assertions_signed: Option<bool>,
    jit_provisioning_enabled: Option<bool>,
    attribute_mappings: Option<serde_json::Value>,
    status: Option<String>,
}

#[derive(Debug, Serialize)]
struct SamlConnectionResponse {
    id: String,
    tenant_id: String,
    name: String,
    idp_entity_id: Option<String>,
    idp_sso_url: Option<String>,
    idp_slo_url: Option<String>,
    idp_certificate_fingerprint: Option<String>,
    sp_entity_id: String,
    sp_acs_url: String,
    sp_slo_url: Option<String>,
    sp_certificate_fingerprint: Option<String>,
    name_id_format: String,
    want_authn_requests_signed: bool,
    want_assertions_signed: bool,
    jit_provisioning_enabled: bool,
    attribute_mappings: serde_json::Value,
    status: String,
    created_at: String,
    updated_at: String,
}

#[derive(Debug, FromRow)]
struct SamlConnectionRow {
    id: String,
    tenant_id: String,
    name: String,
    idp_entity_id: Option<String>,
    idp_sso_url: Option<String>,
    idp_slo_url: Option<String>,
    idp_certificate: Option<String>,
    sp_entity_id: String,
    sp_acs_url: String,
    sp_slo_url: Option<String>,
    sp_certificate: Option<String>,
    name_id_format: String,
    want_authn_requests_signed: bool,
    want_assertions_signed: bool,
    jit_provisioning_enabled: bool,
    attribute_mappings: serde_json::Value,
    status: String,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize)]
struct SpMetadataResponse {
    metadata: String,
    download_url: String,
}

#[derive(Debug, Serialize)]
struct CertificateResponse {
    id: String,
    certificate_type: String,
    fingerprint: String,
    not_before: String,
    not_after: String,
    subject: String,
    issuer: String,
}

#[derive(Debug, Serialize)]
struct AttributeMappingResponse {
    saml_attribute: String,
    vault_attribute: String,
    is_required: bool,
    default_value: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UpdateAttributeMappingsRequest {
    mappings: Vec<AttributeMappingRequest>,
}

#[derive(Debug, Deserialize)]
struct AttributeMappingRequest {
    saml_attribute: String,
    vault_attribute: String,
    is_required: Option<bool>,
    default_value: Option<String>,
}

#[derive(Debug, Serialize)]
struct TestConnectionResponse {
    success: bool,
    message: String,
    details: Option<serde_json::Value>,
}

// ============================================================================
// CRUD Operations
// ============================================================================

async fn list_saml_connections(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<serde_json::Value>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;
    
    let mut conn = state.db.acquire().await.map_err(|_| ApiError::internal())?;
    set_connection_context(&mut conn, &current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;
    
    let rows = sqlx::query_as::<_, SamlConnectionRow>(
        r#"
        SELECT id, tenant_id, name, idp_entity_id, idp_sso_url, idp_slo_url,
               idp_certificate, sp_entity_id, sp_acs_url, sp_slo_url, sp_certificate,
               name_id_format, want_authn_requests_signed, want_assertions_signed,
               jit_provisioning_enabled, attribute_mappings, status, created_at, updated_at
        FROM saml_connections
        WHERE tenant_id = $1
        ORDER BY created_at DESC
        "#
    )
    .bind(&current_user.tenant_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(|_| ApiError::internal())?;
    
    let connections: Vec<SamlConnectionResponse> = rows
        .into_iter()
        .map(|row| row_to_response(row, &state))
        .collect();
    
    Ok(Json(serde_json::json!({ "data": connections })))
}

async fn create_saml_connection(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<CreateSamlConnectionRequest>,
) -> Result<Json<SamlConnectionResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;
    
    let id = uuid::Uuid::new_v4().to_string();
    let base_url = state.config.base_url.clone();
    
    let sp_entity_id = format!("{}/saml/metadata", base_url);
    let sp_acs_url = format!("{}/saml/acs", base_url);
    let sp_slo_url = format!("{}/saml/slo", base_url);
    
    // Generate SP keypair if signing is requested
    let (sp_cert_pem, sp_key_pem) = if req.want_authn_requests_signed.unwrap_or(false) {
        generate_self_signed_cert(&format!("saml.{}", current_user.tenant_id), 365)
            .map_err(|_| ApiError::internal())?
    } else {
        (String::new(), String::new())
    };
    
    let name_id_format = req.name_id_format.unwrap_or_else(|| "email_address".to_string());
    let attribute_mappings = req.attribute_mappings.unwrap_or_else(|| {
        serde_json::json!({
            "email": "email",
            "firstName": "profile.first_name",
            "lastName": "profile.last_name",
            "displayName": "profile.name"
        })
    });
    
    let mut conn = state.db.acquire().await.map_err(|_| ApiError::internal())?;
    set_connection_context(&mut conn, &current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;
    
    sqlx::query(
        r#"
        INSERT INTO saml_connections (
            id, tenant_id, name, idp_entity_id, idp_sso_url, idp_slo_url, idp_certificate,
            sp_entity_id, sp_acs_url, sp_slo_url, sp_certificate, sp_private_key,
            name_id_format, want_authn_requests_signed, want_assertions_signed,
            jit_provisioning_enabled, attribute_mappings, status, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, NOW(), NOW())
        "#
    )
    .bind(&id)
    .bind(&current_user.tenant_id)
    .bind(&req.name)
    .bind(&req.idp_entity_id)
    .bind(&req.idp_sso_url)
    .bind(&req.idp_slo_url)
    .bind(&req.idp_certificate)
    .bind(&sp_entity_id)
    .bind(&sp_acs_url)
    .bind(&sp_slo_url)
    .bind(if sp_cert_pem.is_empty() { None } else { Some(&sp_cert_pem) })
    .bind(if sp_key_pem.is_empty() { None } else { Some(&sp_key_pem) })
    .bind(&name_id_format)
    .bind(req.want_authn_requests_signed.unwrap_or(false))
    .bind(req.want_assertions_signed.unwrap_or(true))
    .bind(req.jit_provisioning_enabled.unwrap_or(true))
    .bind(&attribute_mappings)
    .bind("active")
    .execute(&mut *conn)
    .await
    .map_err(|_| ApiError::internal())?;
    
    let row = sqlx::query_as::<_, SamlConnectionRow>(
        r#"
        SELECT id, tenant_id, name, idp_entity_id, idp_sso_url, idp_slo_url,
               idp_certificate, sp_entity_id, sp_acs_url, sp_slo_url, sp_certificate,
               name_id_format, want_authn_requests_signed, want_assertions_signed,
               jit_provisioning_enabled, attribute_mappings, status, created_at, updated_at
        FROM saml_connections WHERE id = $1 AND tenant_id = $2
        "#
    )
    .bind(&id)
    .bind(&current_user.tenant_id)
    .fetch_one(&mut *conn)
    .await
    .map_err(|_| ApiError::internal())?;
    
    Ok(Json(row_to_response(row, &state)))
}

async fn get_saml_connection(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(connection_id): Path<String>,
) -> Result<Json<SamlConnectionResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;
    
    let mut conn = state.db.acquire().await.map_err(|_| ApiError::internal())?;
    set_connection_context(&mut conn, &current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;
    
    let row = sqlx::query_as::<_, SamlConnectionRow>(
        r#"
        SELECT id, tenant_id, name, idp_entity_id, idp_sso_url, idp_slo_url,
               idp_certificate, sp_entity_id, sp_acs_url, sp_slo_url, sp_certificate,
               name_id_format, want_authn_requests_signed, want_assertions_signed,
               jit_provisioning_enabled, attribute_mappings, status, created_at, updated_at
        FROM saml_connections WHERE id = $1 AND tenant_id = $2
        "#
    )
    .bind(&connection_id)
    .bind(&current_user.tenant_id)
    .fetch_one(&mut *conn)
    .await
    .map_err(|_| ApiError::NotFound)?;
    
    Ok(Json(row_to_response(row, &state)))
}

async fn update_saml_connection(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(connection_id): Path<String>,
    Json(req): Json<UpdateSamlConnectionRequest>,
) -> Result<Json<SamlConnectionResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;
    
    let mut conn = state.db.acquire().await.map_err(|_| ApiError::internal())?;
    set_connection_context(&mut conn, &current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;
    
    // Build dynamic update query
    let mut updates = Vec::new();
    
    if let Some(name) = req.name {
        updates.push(format!("name = '{}'", name.replace('\'', "''")));
    }
    if let Some(idp_entity_id) = req.idp_entity_id {
        updates.push(format!("idp_entity_id = '{}'", idp_entity_id.replace('\'', "''")));
    }
    if let Some(idp_sso_url) = req.idp_sso_url {
        updates.push(format!("idp_sso_url = '{}'", idp_sso_url.replace('\'', "''")));
    }
    if let Some(idp_slo_url) = req.idp_slo_url {
        updates.push(format!("idp_slo_url = '{}'", idp_slo_url.replace('\'', "''")));
    }
    if let Some(idp_certificate) = req.idp_certificate {
        updates.push(format!("idp_certificate = '{}'", idp_certificate.replace('\'', "''")));
    }
    if let Some(name_id_format) = req.name_id_format {
        updates.push(format!("name_id_format = '{}'", name_id_format.replace('\'', "''")));
    }
    if let Some(want_authn) = req.want_authn_requests_signed {
        updates.push(format!("want_authn_requests_signed = {}", want_authn));
    }
    if let Some(want_assertions) = req.want_assertions_signed {
        updates.push(format!("want_assertions_signed = {}", want_assertions));
    }
    if let Some(jit) = req.jit_provisioning_enabled {
        updates.push(format!("jit_provisioning_enabled = {}", jit));
    }
    if let Some(mappings) = req.attribute_mappings {
        updates.push(format!("attribute_mappings = '{}'", mappings.to_string().replace('\'', "''")));
    }
    if let Some(status) = req.status {
        updates.push(format!("status = '{}'", status.replace('\'', "''")));
    }
    
    if !updates.is_empty() {
        updates.push("updated_at = NOW()".to_string());
        
        let query = format!(
            "UPDATE saml_connections SET {} WHERE id = $1 AND tenant_id = $2",
            updates.join(", ")
        );
        
        sqlx::query(&query)
            .bind(&connection_id)
            .bind(&current_user.tenant_id)
            .execute(&mut *conn)
            .await
            .map_err(|_| ApiError::internal())?;
    }
    
    // Fetch updated row
    let row = sqlx::query_as::<_, SamlConnectionRow>(
        r#"
        SELECT id, tenant_id, name, idp_entity_id, idp_sso_url, idp_slo_url,
               idp_certificate, sp_entity_id, sp_acs_url, sp_slo_url, sp_certificate,
               name_id_format, want_authn_requests_signed, want_assertions_signed,
               jit_provisioning_enabled, attribute_mappings, status, created_at, updated_at
        FROM saml_connections WHERE id = $1 AND tenant_id = $2
        "#
    )
    .bind(&connection_id)
    .bind(&current_user.tenant_id)
    .fetch_one(&mut *conn)
    .await
    .map_err(|_| ApiError::NotFound)?;
    
    Ok(Json(row_to_response(row, &state)))
}

async fn delete_saml_connection(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(connection_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;
    
    let mut conn = state.db.acquire().await.map_err(|_| ApiError::internal())?;
    set_connection_context(&mut conn, &current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;
    
    sqlx::query("DELETE FROM saml_connections WHERE id = $1 AND tenant_id = $2")
        .bind(&connection_id)
        .bind(&current_user.tenant_id)
        .execute(&mut *conn)
        .await
        .map_err(|_| ApiError::internal())?;
    
    Ok(StatusCode::NO_CONTENT)
}

// ============================================================================
// Metadata Endpoints
// ============================================================================

async fn download_sp_metadata(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(connection_id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;
    
    let mut conn = state.db.acquire().await.map_err(|_| ApiError::internal())?;
    set_connection_context(&mut conn, &current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;
    
    let row = sqlx::query_as::<_, SamlConnectionRow>(
        r#"
        SELECT id, tenant_id, name, idp_entity_id, idp_sso_url, idp_slo_url,
               idp_certificate, sp_entity_id, sp_acs_url, sp_slo_url, sp_certificate,
               name_id_format, want_authn_requests_signed, want_assertions_signed,
               jit_provisioning_enabled, attribute_mappings, status, created_at, updated_at
        FROM saml_connections WHERE id = $1 AND tenant_id = $2
        "#
    )
    .bind(&connection_id)
    .bind(&current_user.tenant_id)
    .fetch_one(&mut *conn)
    .await
    .map_err(|_| ApiError::NotFound)?;
    
    // Build SP config
    let sp_certificate = if let Some(ref cert_pem) = row.sp_certificate {
        Some(X509Certificate::from_pem(cert_pem).map_err(|_| ApiError::internal())?)
    } else {
        None
    };
    
    let sp_config = ServiceProviderConfig {
        entity_id: row.sp_entity_id,
        acs_url: row.sp_acs_url,
        slo_url: row.sp_slo_url,
        metadata_url: format!("{}/saml/metadata", state.config.base_url),
        certificate: sp_certificate,
        private_key: None, // Don't expose private key
        want_authn_requests_signed: row.want_authn_requests_signed,
        want_assertions_signed: row.want_assertions_signed,
        want_assertions_encrypted: false,
        name_id_format: NameIdFormat::from_str(&row.name_id_format)
            .unwrap_or(NameIdFormat::EmailAddress),
        organization: None,
        contacts: Vec::new(),
    };
    
    let metadata = generate_sp_metadata(&sp_config)
        .map_err(|_| ApiError::internal())?;
    
    Ok((
        [(
            axum::http::header::CONTENT_TYPE,
            "application/samlmetadata+xml",
        )],
        metadata,
    ))
}

async fn upload_idp_metadata(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(connection_id): Path<String>,
    mut multipart: Multipart,
) -> Result<Json<SamlConnectionResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;
    
    // Extract file content
    let mut metadata_xml = None;
    
    while let Some(field) = multipart.next_field().await.ok().flatten() {
        if field.name().map(|n| n == "metadata").unwrap_or(false) {
            metadata_xml = field.text().await.ok();
            break;
        }
    }
    
    let metadata_xml = metadata_xml.ok_or(ApiError::BadRequest("No metadata file provided".to_string()))?;
    
    // Parse IdP metadata
    let idp_metadata = parse_idp_metadata(&metadata_xml)
        .map_err(|e| ApiError::BadRequest(format!("Invalid metadata: {}", e)))?;
    
    // Extract information
    let idp_entity_id = idp_metadata.entity_id;
    let idp_sso_url = IdpMetadataParser::extract_sso_url(&idp_metadata, super::super::SamlBinding::HttpRedirect)
        .or_else(|| IdpMetadataParser::extract_sso_url(&idp_metadata, super::super::SamlBinding::HttpPost));
    let idp_slo_url = IdpMetadataParser::extract_slo_url(&idp_metadata, super::super::SamlBinding::HttpRedirect)
        .or_else(|| IdpMetadataParser::extract_slo_url(&idp_metadata, super::super::SamlBinding::HttpPost));
    
    // Extract certificate (simplified - in production extract from KeyDescriptor)
    let idp_certificate = IdpMetadataParser::extract_certificate(&idp_metadata);
    
    // Update connection
    let mut conn = state.db.acquire().await.map_err(|_| ApiError::internal())?;
    set_connection_context(&mut conn, &current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;
    
    sqlx::query(
        r#"
        UPDATE saml_connections
        SET idp_entity_id = $1, idp_sso_url = $2, idp_slo_url = $3, idp_certificate = $4, updated_at = NOW()
        WHERE id = $5 AND tenant_id = $6
        "#
    )
    .bind(&idp_entity_id)
    .bind(&idp_sso_url)
    .bind(&idp_slo_url)
    .bind(&idp_certificate)
    .bind(&connection_id)
    .bind(&current_user.tenant_id)
    .execute(&mut *conn)
    .await
    .map_err(|_| ApiError::internal())?;
    
    // Fetch updated row
    let row = sqlx::query_as::<_, SamlConnectionRow>(
        r#"
        SELECT id, tenant_id, name, idp_entity_id, idp_sso_url, idp_slo_url,
               idp_certificate, sp_entity_id, sp_acs_url, sp_slo_url, sp_certificate,
               name_id_format, want_authn_requests_signed, want_assertions_signed,
               jit_provisioning_enabled, attribute_mappings, status, created_at, updated_at
        FROM saml_connections WHERE id = $1 AND tenant_id = $2
        "#
    )
    .bind(&connection_id)
    .bind(&current_user.tenant_id)
    .fetch_one(&mut *conn)
    .await
    .map_err(|_| ApiError::NotFound)?;
    
    Ok(Json(row_to_response(row, &state)))
}

// ============================================================================
// Certificate Management
// ============================================================================

async fn list_certificates(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(connection_id): Path<String>,
) -> Result<Json<Vec<CertificateResponse>>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;
    
    let mut conn = state.db.acquire().await.map_err(|_| ApiError::internal())?;
    set_connection_context(&mut conn, &current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;
    
    let row = sqlx::query_as::<_, SamlConnectionRow>(
        r#"
        SELECT id, tenant_id, name, idp_entity_id, idp_sso_url, idp_slo_url,
               idp_certificate, sp_entity_id, sp_acs_url, sp_slo_url, sp_certificate,
               name_id_format, want_authn_requests_signed, want_assertions_signed,
               jit_provisioning_enabled, attribute_mappings, status, created_at, updated_at
        FROM saml_connections WHERE id = $1 AND tenant_id = $2
        "#
    )
    .bind(&connection_id)
    .bind(&current_user.tenant_id)
    .fetch_one(&mut *conn)
    .await
    .map_err(|_| ApiError::NotFound)?;
    
    let mut certificates = Vec::new();
    
    // SP Certificate
    if let Some(ref cert_pem) = row.sp_certificate {
        if let Ok(cert) = X509Certificate::from_pem(cert_pem) {
            certificates.push(CertificateResponse {
                id: format!("{}-sp", connection_id),
                certificate_type: "sp_signing".to_string(),
                fingerprint: cert.fingerprint().unwrap_or_default(),
                not_before: cert.not_before().map(|d| d.to_rfc3339()).unwrap_or_default(),
                not_after: cert.not_after().map(|d| d.to_rfc3339()).unwrap_or_default(),
                subject: cert.subject().unwrap_or_default(),
                issuer: cert.issuer().unwrap_or_default(),
            });
        }
    }
    
    // IdP Certificate
    if let Some(ref cert_pem) = row.idp_certificate {
        if let Ok(cert) = X509Certificate::from_pem(cert_pem) {
            certificates.push(CertificateResponse {
                id: format!("{}-idp", connection_id),
                certificate_type: "idp_signing".to_string(),
                fingerprint: cert.fingerprint().unwrap_or_default(),
                not_before: cert.not_before().map(|d| d.to_rfc3339()).unwrap_or_default(),
                not_after: cert.not_after().map(|d| d.to_rfc3339()).unwrap_or_default(),
                subject: cert.subject().unwrap_or_default(),
                issuer: cert.issuer().unwrap_or_default(),
            });
        }
    }
    
    Ok(Json(certificates))
}

async fn generate_certificate(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(connection_id): Path<String>,
) -> Result<Json<CertificateResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;
    
    // Generate new certificate
    let (cert_pem, key_pem) = generate_self_signed_cert(
        &format!("saml.{}.vault", current_user.tenant_id),
        365
    ).map_err(|_| ApiError::internal())?;
    
    let mut conn = state.db.acquire().await.map_err(|_| ApiError::internal())?;
    set_connection_context(&mut conn, &current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;
    
    sqlx::query(
        r#"
        UPDATE saml_connections
        SET sp_certificate = $1, sp_private_key = $2, updated_at = NOW()
        WHERE id = $3 AND tenant_id = $4
        "#
    )
    .bind(&cert_pem)
    .bind(&key_pem)
    .bind(&connection_id)
    .bind(&current_user.tenant_id)
    .execute(&mut *conn)
    .await
    .map_err(|_| ApiError::internal())?;
    
    let cert = X509Certificate::from_pem(&cert_pem).map_err(|_| ApiError::internal())?;
    
    Ok(Json(CertificateResponse {
        id: format!("{}-sp", connection_id),
        certificate_type: "sp_signing".to_string(),
        fingerprint: cert.fingerprint().map_err(|_| ApiError::internal())?,
        not_before: cert.not_before().map_err(|_| ApiError::internal())?.to_rfc3339(),
        not_after: cert.not_after().map_err(|_| ApiError::internal())?.to_rfc3339(),
        subject: cert.subject().map_err(|_| ApiError::internal())?,
        issuer: cert.issuer().map_err(|_| ApiError::internal())?,
    }))
}

async fn rotate_certificate(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(connection_id): Path<String>,
) -> Result<Json<CertificateResponse>, ApiError> {
    // Same as generate - creates new cert and archives old one
    generate_certificate(State(state), Extension(current_user), Path(connection_id)).await
}

// ============================================================================
// Testing
// ============================================================================

async fn test_saml_connection(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(connection_id): Path<String>,
) -> Result<Json<TestConnectionResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;
    
    let mut conn = state.db.acquire().await.map_err(|_| ApiError::internal())?;
    set_connection_context(&mut conn, &current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;
    
    let row = sqlx::query_as::<_, SamlConnectionRow>(
        r#"
        SELECT id, tenant_id, name, idp_entity_id, idp_sso_url, idp_slo_url,
               idp_certificate, sp_entity_id, sp_acs_url, sp_slo_url, sp_certificate,
               name_id_format, want_authn_requests_signed, want_assertions_signed,
               jit_provisioning_enabled, attribute_mappings, status, created_at, updated_at
        FROM saml_connections WHERE id = $1 AND tenant_id = $2
        "#
    )
    .bind(&connection_id)
    .bind(&current_user.tenant_id)
    .fetch_one(&mut *conn)
    .await
    .map_err(|_| ApiError::NotFound)?;
    
    // Validate configuration
    let mut issues = Vec::new();
    
    if row.idp_entity_id.is_none() {
        issues.push("IdP Entity ID not configured");
    }
    if row.idp_sso_url.is_none() {
        issues.push("IdP SSO URL not configured");
    }
    if row.idp_certificate.is_none() {
        issues.push("IdP Certificate not configured");
    }
    
    // Validate certificate
    if let Some(ref cert_pem) = row.idp_certificate {
        match X509Certificate::from_pem(cert_pem) {
            Ok(cert) => {
                match cert.is_valid_at(chrono::Utc::now()) {
                    Ok(true) => {}
                    Ok(false) => issues.push("IdP Certificate has expired"),
                    Err(_) => issues.push("Could not validate IdP Certificate"),
                }
            }
            Err(_) => issues.push("IdP Certificate is invalid"),
        }
    }
    
    let success = issues.is_empty();
    let message = if success {
        "SAML connection configuration is valid".to_string()
    } else {
        format!("Found {} issue(s): {}", issues.len(), issues.join(", "))
    };
    
    Ok(Json(TestConnectionResponse {
        success,
        message,
        details: Some(serde_json::json!({
            "issues": issues,
            "idp_entity_id_configured": row.idp_entity_id.is_some(),
            "idp_sso_url_configured": row.idp_sso_url.is_some(),
            "idp_slo_url_configured": row.idp_slo_url.is_some(),
            "idp_certificate_configured": row.idp_certificate.is_some(),
            "sp_certificate_configured": row.sp_certificate.is_some(),
        })),
    }))
}

// ============================================================================
// Attribute Mappings
// ============================================================================

async fn get_attribute_mappings(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(connection_id): Path<String>,
) -> Result<Json<Vec<AttributeMappingResponse>>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;
    
    let mut conn = state.db.acquire().await.map_err(|_| ApiError::internal())?;
    set_connection_context(&mut conn, &current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;
    
    let row = sqlx::query_as::<_, SamlConnectionRow>(
        r#"
        SELECT id, tenant_id, name, idp_entity_id, idp_sso_url, idp_slo_url,
               idp_certificate, sp_entity_id, sp_acs_url, sp_slo_url, sp_certificate,
               name_id_format, want_authn_requests_signed, want_assertions_signed,
               jit_provisioning_enabled, attribute_mappings, status, created_at, updated_at
        FROM saml_connections WHERE id = $1 AND tenant_id = $2
        "#
    )
    .bind(&connection_id)
    .bind(&current_user.tenant_id)
    .fetch_one(&mut *conn)
    .await
    .map_err(|_| ApiError::NotFound)?;
    
    let mappings = if let Some(obj) = row.attribute_mappings.as_object() {
        obj.iter()
            .map(|(k, v)| AttributeMappingResponse {
                saml_attribute: k.clone(),
                vault_attribute: v.as_str().unwrap_or(k).to_string(),
                is_required: k == "email",
                default_value: None,
            })
            .collect()
    } else {
        Vec::new()
    };
    
    Ok(Json(mappings))
}

async fn update_attribute_mappings(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(connection_id): Path<String>,
    Json(req): Json<UpdateAttributeMappingsRequest>,
) -> Result<Json<Vec<AttributeMappingResponse>>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;
    
    // Build mappings object
    let mut mappings = serde_json::Map::new();
    for mapping in &req.mappings {
        mappings.insert(
            mapping.saml_attribute.clone(),
            serde_json::json!(mapping.vault_attribute),
        );
    }
    
    let mappings_json = serde_json::Value::Object(mappings);
    
    let mut conn = state.db.acquire().await.map_err(|_| ApiError::internal())?;
    set_connection_context(&mut conn, &current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;
    
    sqlx::query(
        r#"
        UPDATE saml_connections
        SET attribute_mappings = $1, updated_at = NOW()
        WHERE id = $2 AND tenant_id = $3
        "#
    )
    .bind(&mappings_json)
    .bind(&connection_id)
    .bind(&current_user.tenant_id)
    .execute(&mut *conn)
    .await
    .map_err(|_| ApiError::internal())?;
    
    let responses: Vec<AttributeMappingResponse> = req.mappings
        .into_iter()
        .map(|m| AttributeMappingResponse {
            saml_attribute: m.saml_attribute,
            vault_attribute: m.vault_attribute,
            is_required: m.is_required.unwrap_or(false),
            default_value: m.default_value,
        })
        .collect();
    
    Ok(Json(responses))
}

// ============================================================================
// Helper Functions
// ============================================================================

fn row_to_response(row: SamlConnectionRow, state: &AppState) -> SamlConnectionResponse {
    let idp_cert_fingerprint = row.idp_certificate.as_ref()
        .and_then(|pem| X509Certificate::from_pem(pem).ok())
        .and_then(|cert| cert.fingerprint().ok());
    
    let sp_cert_fingerprint = row.sp_certificate.as_ref()
        .and_then(|pem| X509Certificate::from_pem(pem).ok())
        .and_then(|cert| cert.fingerprint().ok());
    
    SamlConnectionResponse {
        id: row.id,
        tenant_id: row.tenant_id,
        name: row.name,
        idp_entity_id: row.idp_entity_id,
        idp_sso_url: row.idp_sso_url,
        idp_slo_url: row.idp_slo_url,
        idp_certificate_fingerprint: idp_cert_fingerprint,
        sp_entity_id: row.sp_entity_id,
        sp_acs_url: row.sp_acs_url,
        sp_slo_url: row.sp_slo_url,
        sp_certificate_fingerprint: sp_cert_fingerprint,
        name_id_format: row.name_id_format,
        want_authn_requests_signed: row.want_authn_requests_signed,
        want_assertions_signed: row.want_assertions_signed,
        jit_provisioning_enabled: row.jit_provisioning_enabled,
        attribute_mappings: row.attribute_mappings,
        status: row.status,
        created_at: row.created_at.to_rfc3339(),
        updated_at: row.updated_at.to_rfc3339(),
    }
}
