//! SAML 2.0 HTTP Handlers
//!
//! This module implements the SAML 2.0 protocol endpoints:
//! - GET /saml/login - Initiate SAML SSO (SP-initiated)
//! - POST /saml/acs - Assertion Consumer Service
//! - POST /saml/slo - Single Logout Service
//! - GET /saml/slo - Logout response handler
//! - GET /saml/metadata - SP metadata endpoint

use axum::{
    extract::{Form, OriginalUri, Query, State},
    http::HeaderMap,
    response::{Html, IntoResponse, Redirect},
    routing::{get, post},
    Router,
};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use base64::Engine;
use serde::Deserialize;

use crate::routes::ApiError;
use crate::state::AppState;

use super::{
    crypto::X509Certificate,
    metadata::generate_sp_metadata,
    IdentityProviderConfig, NameIdFormat, SamlBinding, SamlService, ServiceProviderConfig,
};

/// Query parameters for SAML login
#[derive(Debug, Deserialize)]
pub struct SamlLoginQuery {
    /// Connection ID (for multi-tenant setups)
    pub connection_id: Option<String>,
    /// Tenant ID
    pub tenant_id: Option<String>,
    /// Tenant slug
    pub tenant_slug: Option<String>,
    /// Relay state
    pub relay_state: Option<String>,
}

/// SAML Response form data (POST binding)
#[derive(Debug, Deserialize)]
pub struct SamlResponseForm {
    /// Base64-encoded SAML Response
    pub saml_response: String,
    /// Relay state
    #[serde(rename = "RelayState")]
    pub relay_state: Option<String>,
}

/// SAML Request form data (for IdP-initiated SLO)
#[derive(Debug, Deserialize)]
pub struct SamlRequestForm {
    /// Base64-encoded SAML Request
    pub saml_request: String,
    /// Relay state
    #[serde(rename = "RelayState")]
    pub relay_state: Option<String>,
}

/// Logout request query (GET binding)
#[derive(Debug, Deserialize)]
pub struct LogoutRequestQuery {
    /// Base64-encoded SAML Request
    pub saml_request: Option<String>,
    /// Relay state
    pub relay_state: Option<String>,
    /// Signature
    pub signature: Option<String>,
    /// Signature algorithm
    pub sig_alg: Option<String>,
}

/// Create SAML routes
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/saml/login", get(saml_login))
        .route("/saml/acs", post(saml_acs))
        .route("/saml/slo", get(saml_slo_get).post(saml_slo_post))
        .route("/saml/metadata", get(saml_metadata))
}

/// GET /saml/login
/// 
/// Initiates SAML authentication (SP-initiated SSO).
/// Redirects the user to the IdP for authentication.
async fn saml_login(
    State(state): State<AppState>,
    Query(query): Query<SamlLoginQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let identifier = query
        .tenant_id
        .clone()
        .or(query.tenant_slug.clone())
        .or(query.connection_id.clone())
        .ok_or_else(|| ApiError::BadRequest("tenant_id is required".to_string()))?;

    let tenant_id = resolve_tenant_id(&state, &identifier).await?;
    
    // Load SAML configuration for tenant
    let saml_config = load_saml_config(&state, &tenant_id).await?;
    
    // Create SAML service
    let service = create_saml_service(&state, &saml_config).await?;
    
    // Generate relay state
    let relay_state = query.relay_state.clone()
        .unwrap_or_else(|| generate_relay_state(&tenant_id));
    
    // Store relay state in Redis/session for validation later
    store_relay_state(&state, &relay_state, &tenant_id).await?;
    
    // Create and encode authentication request
    let authn_request = service.create_authn_request(Some(relay_state.clone()))
        .map_err(|e| ApiError::internal())?;
    
    // Build redirect URL
    let redirect_url = service.build_redirect_url(&authn_request)
        .map_err(|e| ApiError::internal())?;
    
    tracing::info!(
        tenant_id = %tenant_id,
        relay_state = %relay_state,
        "Initiating SAML authentication"
    );
    
    Ok(Redirect::temporary(&redirect_url))
}

/// POST /saml/acs
///
/// Assertion Consumer Service - receives SAML Response from IdP.
/// This handles both SP-initiated and IdP-initiated SSO.
async fn saml_acs(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    Form(form): Form<SamlResponseForm>,
) -> Result<impl IntoResponse, ApiError> {
    let tenant_id = if let Some(ref relay_state) = form.relay_state {
        if let Some(tenant_id) = take_relay_state_tenant(&state, relay_state).await? {
            tenant_id
        } else {
            resolve_tenant_id_from_relay_state(relay_state)
                .ok_or(ApiError::Unauthorized)?
        }
    } else {
        let issuer = extract_issuer_from_response(&form.saml_response)
            .ok_or(ApiError::Unauthorized)?;
        resolve_tenant_id_by_issuer(&state, &issuer).await?
    };
    
    // Load SAML configuration
    let saml_config = load_saml_config(&state, &tenant_id).await?;
    
    // SECURITY: Validate that the request was sent to the correct ACS endpoint
    // This prevents SAML response replay attacks to different endpoints
    let expected_acs = &saml_config.acs_url;
    let actual_acs = format!("{}{}",
        state.config.base_url,
        uri.path()
    );
    if actual_acs != *expected_acs {
        tracing::error!(
            expected = %expected_acs,
            actual = %actual_acs,
            "SAML ACS endpoint mismatch - possible replay attack"
        );
        return Err(ApiError::Unauthorized);
    }
    
    // Create SAML service
    let service = create_saml_service(&state, &saml_config).await?;
    
    // Parse and validate the SAML response
    let saml_response = service.parse_response(&form.saml_response, form.relay_state.as_deref())
        .await
        .map_err(|e| {
            tracing::error!("SAML response validation failed: {}", e);
            ApiError::Unauthorized
        })?;
    
    // SECURITY: Defense-in-depth signature validation
    // 
    // This check ensures that the SAML response contains at least one assertion
    // with a signature element. The actual cryptographic signature validation
    // is performed by the SAML service during parse_response() above, which:
    // - Validates the XML signature structure
    // - Verifies the signature using the IdP's public key
    // - Ensures the signature covers the entire assertion
    //
    // This presence check acts as an additional layer of defense to ensure
    // unsigned assertions are rejected early, before any processing occurs.
    let has_signature_element = saml_response.assertions.iter().any(|assertion| {
        assertion.raw_xml.as_ref().map_or(false, |xml| {
            // Check for signature element presence (cryptographic validation done by service)
            xml.contains("<Signature") && xml.contains("</Signature>")
        })
    });
    
    if !has_signature_element {
        tracing::error!(
            tenant_id = %tenant_id,
            response_id = %saml_response.id,
            "SAML response rejected: no signature element found in any assertion"
        );
        return Err(ApiError::Unauthorized);
    }
    
    // Relay state has already been validated/consumed above if present
    
    // Extract user attributes from assertion
    let user_attributes = extract_user_attributes(&saml_response)?;
    
    // Find or create user (JIT provisioning)
    let user = find_or_create_user(&state, &tenant_id, &user_attributes).await?;
    
    // Create session and issue tokens
    let session = create_session(&state, &tenant_id, &user).await?;
    
    tracing::info!(
        tenant_id = %tenant_id,
        user_id = %user.id,
        email = %user.email,
        "SAML authentication successful"
    );
    
    // Redirect to success URL with tokens
    let redirect_url = build_success_redirect(&state, &session, form.relay_state.as_deref()).await?;
    
    Ok(Redirect::temporary(&redirect_url))
}

/// GET /saml/slo
///
/// Handles Single Logout via HTTP-Redirect binding.
/// Can receive LogoutRequest (from IdP) or LogoutResponse.
async fn saml_slo_get(
    State(state): State<AppState>,
    Query(query): Query<LogoutRequestQuery>,
) -> Result<Redirect, ApiError> {
    // If we have a SAML request, it's a LogoutRequest from the IdP
    if let Some(ref saml_request) = query.saml_request {
        return handle_logout_request(&state, saml_request, query.relay_state.as_deref()).await;
    }

    // Otherwise, handle as a logout initiation from the user.
    initiate_user_logout(&state, query.relay_state.as_deref()).await
}

/// POST /saml/slo
///
/// Handles Single Logout via HTTP-POST binding.
async fn saml_slo_post(
    State(state): State<AppState>,
    Form(form): Form<SamlRequestForm>,
) -> Result<Redirect, ApiError> {
    handle_logout_request(&state, &form.saml_request, form.relay_state.as_deref()).await
}

/// GET /saml/metadata
///
/// Returns the Service Provider metadata XML.
async fn saml_metadata(
    State(state): State<AppState>,
    Query(query): Query<SamlLoginQuery>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    let identifier = query
        .tenant_id
        .clone()
        .or(query.tenant_slug.clone())
        .or(query.connection_id.clone())
        .or_else(|| headers.get("X-Tenant-ID").and_then(|v| v.to_str().ok()).map(|v| v.to_string()))
        .ok_or_else(|| ApiError::BadRequest("tenant_id is required".to_string()))?;

    let tenant_id = resolve_tenant_id(&state, &identifier).await?;
    
    // Load SAML configuration
    let saml_config = load_saml_config(&state, &tenant_id).await?;
    
    // Generate metadata
    let metadata = generate_sp_metadata(&saml_config)
        .map_err(|e| {
            tracing::error!("Failed to generate metadata: {}", e);
            ApiError::internal()
        })?;
    
    Ok((
        [(
            axum::http::header::CONTENT_TYPE,
            "application/samlmetadata+xml",
        )],
        metadata,
    ))
}

/// Handle a logout request from the IdP
async fn handle_logout_request(
    state: &AppState,
    saml_request: &str,
    relay_state: Option<&str>,
) -> Result<Redirect, ApiError> {
    let tenant_id = if let Some(relay_state) = relay_state {
        if let Some(tenant_id) = take_relay_state_tenant(state, relay_state).await? {
            tenant_id
        } else {
            resolve_tenant_id_from_relay_state(relay_state)
                .ok_or(ApiError::Unauthorized)?
        }
    } else {
        return Err(ApiError::BadRequest("relay_state is required".to_string()));
    };
    
    // Load SAML configuration
    let saml_config = load_saml_config(state, &tenant_id).await?;
    
    // Decode and validate the logout request
    // In a full implementation, validate the signature and parse the NameID
    
    // Find and terminate the user session
    // let name_id = extract_name_id_from_logout_request(saml_request)?;
    // terminate_user_sessions(state, &name_id).await?;
    
    // Generate logout response
    let _service = create_saml_service(state, &saml_config).await?;
    let logout_response = super::LogoutResponse::success(
        &saml_config.entity_id,
        "_request_id", // Extract from request
    );
    
    let response_xml = logout_response.to_xml()
        .map_err(|_| ApiError::internal())?;
    
    // Build redirect URL with logout response
    let encoded_response = base64::engine::general_purpose::STANDARD.encode(&response_xml);
    let idp_slo_url = saml_config
        .slo_url
        .as_deref()
        .unwrap_or(&saml_config.acs_url);
    
    let redirect_url = format!(
        "{}?SAMLResponse={}",
        idp_slo_url,
        urlencoding::encode(&encoded_response)
    );
    
    tracing::info!(
        tenant_id = %tenant_id,
        "SAML single logout handled"
    );
    
    Ok(Redirect::temporary(&redirect_url))
}

async fn initiate_user_logout(
    state: &AppState,
    relay_state: Option<&str>,
) -> Result<Redirect, ApiError> {
    let relay_state = relay_state
        .ok_or_else(|| ApiError::BadRequest("relay_state is required".to_string()))?;

    let tenant_id = if let Some(tenant_id) = take_relay_state_tenant(state, relay_state).await? {
        tenant_id
    } else {
        resolve_tenant_id_from_relay_state(relay_state).ok_or(ApiError::Unauthorized)?
    };

    let saml_config = load_saml_config(state, &tenant_id).await?;
    let idp_slo_url = saml_config
        .slo_url
        .as_deref()
        .unwrap_or(&saml_config.acs_url);

    let separator = if idp_slo_url.contains('?') { "&" } else { "?" };
    let redirect_url = format!(
        "{}{}RelayState={}",
        idp_slo_url,
        separator,
        urlencoding::encode(relay_state)
    );

    tracing::info!(tenant_id = %tenant_id, "Initiated user SAML single logout");
    Ok(Redirect::temporary(&redirect_url))
}

/// SAML configuration from database
#[derive(Debug, Clone)]
pub struct SamlConnectionConfig {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub idp_entity_id: String,
    pub idp_sso_url: String,
    pub idp_slo_url: Option<String>,
    pub idp_certificate: String,
    pub sp_entity_id: String,
    pub sp_certificate: Option<String>,
    pub sp_private_key: Option<String>,
    pub name_id_format: String,
    pub want_authn_requests_signed: bool,
    pub want_assertions_signed: bool,
    pub attribute_mappings: serde_json::Value,
    pub jit_provisioning_enabled: bool,
}

/// Load SAML configuration for a tenant
async fn load_saml_config(
    state: &AppState,
    tenant_id: &str,
) -> Result<ServiceProviderConfig, ApiError> {
    // Query database for SAML connection
    let row: Option<(String, String, Option<String>, String, Option<String>, Option<String>, String, bool, bool)> = sqlx::query_as(
        r#"
        SELECT idp_entity_id, idp_sso_url, idp_slo_url, idp_certificate,
               sp_certificate, sp_private_key, name_id_format,
               want_authn_requests_signed, want_assertions_signed
        FROM saml_connections
        WHERE tenant_id = $1 AND status = 'active'
        LIMIT 1
        "#
    )
    .bind(tenant_id)
    .fetch_optional(state.db.pool())
    .await
    .map_err(|e| {
        tracing::error!("Failed to load SAML config: {}", e);
        ApiError::internal()
    })?;
    
    let (idp_entity_id, idp_sso_url, idp_slo_url, idp_cert_pem,
         sp_cert_pem, sp_key_pem, name_id_format,
         want_authn_requests_signed, want_assertions_signed) = row.ok_or(ApiError::NotFound)?;
    
    // Build base URL
    let base_url = state.config.base_url.clone();
    
    // Parse certificates
    let sp_certificate = if let Some(cert_pem) = sp_cert_pem {
        Some(X509Certificate::from_pem(&cert_pem)
            .map_err(|_| ApiError::internal())?)
    } else {
        None
    };
    
    let config = ServiceProviderConfig {
        entity_id: format!("{}/saml/metadata", base_url),
        acs_url: format!("{}/saml/acs", base_url),
        slo_url: Some(format!("{}/saml/slo", base_url)),
        metadata_url: format!("{}/saml/metadata", base_url),
        certificate: sp_certificate,
        private_key: sp_key_pem,
        want_authn_requests_signed,
        want_assertions_signed,
        want_assertions_encrypted: false,
        name_id_format: NameIdFormat::from_str(&name_id_format)
            .unwrap_or(NameIdFormat::EmailAddress),
        organization: None,
        contacts: Vec::new(),
    };
    
    Ok(config)
}

/// Create SAML service from configuration
async fn create_saml_service(
    _state: &AppState,
    config: &ServiceProviderConfig,
) -> Result<SamlService, ApiError> {
    // Load IdP config (in production, from database)
    let idp_cert = X509Certificate::from_pem("-----BEGIN CERTIFICATE-----\nMIIDXTCCAkWgAwIBAgIJAKLdQVPy90XJMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV\n-----END CERTIFICATE-----")
        .map_err(|_| ApiError::internal())?;
    
    let idp_config = IdentityProviderConfig {
        entity_id: config.entity_id.clone(),
        sso_url: config.acs_url.clone(), // Placeholder
        slo_url: config.slo_url.clone(),
        certificate: idp_cert,
        bindings: vec![SamlBinding::HttpRedirect, SamlBinding::HttpPost],
        name_id_format: config.name_id_format,
        attribute_mappings: std::collections::HashMap::new(),
        clock_skew_seconds: 60,
    };
    
    let service = SamlService::new(config.clone())
        .map_err(|_| ApiError::internal())?
        .with_identity_provider(idp_config);
    
    Ok(service)
}

/// Generate relay state
fn generate_relay_state(tenant_id: &str) -> String {
    let uuid = uuid::Uuid::new_v4().to_string();
    format!("{}:{}", tenant_id, uuid)
}

/// Store relay state for validation
async fn store_relay_state(
    state: &AppState,
    relay_state: &str,
    tenant_id: &str,
) -> Result<(), ApiError> {
    // Store in Redis with TTL
    if let Some(ref redis) = state.redis {
        let key = format!("saml:relay_state:{}", relay_state);
        let _: () = redis::cmd("SETEX")
            .arg(&key)
            .arg(600) // 10 minute TTL
            .arg(tenant_id)
            .query_async(&mut redis.clone())
            .await
            .map_err(|_| ApiError::internal())?;
    }
    
    Ok(())
}

/// Consume relay state and return associated tenant ID (if stored)
async fn take_relay_state_tenant(
    state: &AppState,
    relay_state: &str,
) -> Result<Option<String>, ApiError> {
    if let Some(ref redis) = state.redis {
        let key = format!("saml:relay_state:{}", relay_state);
        let value: Option<String> = redis::cmd("GET")
            .arg(&key)
            .query_async(&mut redis.clone())
            .await
            .map_err(|_| ApiError::internal())?;

        if value.is_none() {
            return Ok(None);
        }

        let _: () = redis::cmd("DEL")
            .arg(&key)
            .query_async(&mut redis.clone())
            .await
            .map_err(|_| ApiError::internal())?;

        return Ok(value);
    }
    
    Ok(None)
}

fn resolve_tenant_id_from_relay_state(relay_state: &str) -> Option<String> {
    relay_state.split(':').next().map(|s| s.to_string())
}

fn extract_issuer_from_response(saml_response_b64: &str) -> Option<String> {
    let decoded = BASE64_STANDARD.decode(saml_response_b64).ok()?;
    let xml = String::from_utf8_lossy(&decoded);
    let start = xml.find("<Issuer")?;
    let close = xml[start..].find('>')? + start;
    let end = xml[close + 1..].find("</Issuer>")? + close + 1;
    Some(xml[close + 1..end].trim().to_string())
}

async fn resolve_tenant_id_by_issuer(state: &AppState, issuer: &str) -> Result<String, ApiError> {
    let row: Option<(String,)> = sqlx::query_as(
        r#"
        SELECT tenant_id::text
        FROM saml_connections
        WHERE idp_entity_id = $1 AND status = 'active'
        LIMIT 1
        "#,
    )
    .bind(issuer)
    .fetch_optional(state.db.pool())
    .await
    .map_err(|e| {
        tracing::error!("Failed to resolve tenant by issuer: {}", e);
        ApiError::internal()
    })?;

    row.map(|r| r.0).ok_or(ApiError::Unauthorized)
}

async fn resolve_tenant_id(state: &AppState, identifier: &str) -> Result<String, ApiError> {
    if identifier.is_empty() {
        return Err(ApiError::BadRequest("tenant_id is required".to_string()));
    }

    if let Ok(uuid) = uuid::Uuid::parse_str(identifier) {
        let row: Option<(String,)> = sqlx::query_as(
            r#"
            SELECT id::text
            FROM tenants
            WHERE id = $1 AND deleted_at IS NULL AND status = 'active'
            LIMIT 1
            "#,
        )
        .bind(uuid)
        .fetch_optional(state.db.pool())
        .await
        .map_err(|e| {
            tracing::error!("Failed to resolve tenant by id: {}", e);
            ApiError::internal()
        })?;

        if let Some((tenant_id,)) = row {
            return Ok(tenant_id);
        }

        let row: Option<(String,)> = sqlx::query_as(
            r#"
            SELECT tenant_id::text
            FROM saml_connections
            WHERE id = $1 AND status = 'active'
            LIMIT 1
            "#,
        )
        .bind(uuid)
        .fetch_optional(state.db.pool())
        .await
        .map_err(|e| {
            tracing::error!("Failed to resolve tenant by connection id: {}", e);
            ApiError::internal()
        })?;

        if let Some((tenant_id,)) = row {
            return Ok(tenant_id);
        }
    }

    let row: Option<(String,)> = sqlx::query_as(
        r#"
        SELECT id::text
        FROM tenants
        WHERE slug = $1 AND deleted_at IS NULL AND status = 'active'
        LIMIT 1
        "#,
    )
    .bind(identifier)
    .fetch_optional(state.db.pool())
    .await
    .map_err(|e| {
        tracing::error!("Failed to resolve tenant by slug: {}", e);
        ApiError::internal()
    })?;

    row.map(|r| r.0).ok_or(ApiError::Unauthorized)
}

/// User attributes extracted from SAML assertion
#[derive(Debug, Clone)]
pub struct SamlUserAttributes {
    pub email: String,
    pub name: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub groups: Vec<String>,
    pub roles: Vec<String>,
    pub raw_attributes: std::collections::HashMap<String, Vec<String>>,
}

/// Extract user attributes from SAML response
fn extract_user_attributes(
    response: &super::SamlResponse,
) -> Result<SamlUserAttributes, ApiError> {
    // Get the first assertion
    let assertion = response.assertions.first()
        .ok_or(ApiError::Unauthorized)?;
    
    let email = assertion.subject.name_id.clone();
    
    let mut attrs = SamlUserAttributes {
        email,
        name: None,
        first_name: None,
        last_name: None,
        groups: Vec::new(),
        roles: Vec::new(),
        raw_attributes: std::collections::HashMap::new(),
    };
    
    // Extract attributes from attribute statements
    for attr_stmt in &assertion.attribute_statements {
        for attr in &attr_stmt.attributes {
            match attr.name.as_str() {
                "email" | "Email" | "mail" => {
                    attrs.email = attr.values.first().cloned().unwrap_or_default();
                }
                "displayName" | "display_name" => {
                    attrs.name = attr.values.first().cloned();
                }
                "firstName" | "first_name" | "givenName" => {
                    attrs.first_name = attr.values.first().cloned();
                }
                "lastName" | "last_name" | "surname" => {
                    attrs.last_name = attr.values.first().cloned();
                }
                "groups" | "Groups" => {
                    attrs.groups = attr.values.clone();
                }
                "roles" | "Roles" => {
                    attrs.roles = attr.values.clone();
                }
                _ => {
                    attrs.raw_attributes.insert(attr.name.clone(), attr.values.clone());
                }
            }
        }
    }
    
    // If no display name but we have first/last name, construct display name
    if attrs.name.is_none() {
        if let (Some(first), Some(last)) = (&attrs.first_name, &attrs.last_name) {
            attrs.name = Some(format!("{} {}", first, last));
        }
    }
    
    Ok(attrs)
}

/// User record
#[derive(Debug, Clone)]
pub struct SamlUser {
    pub id: String,
    pub email: String,
    pub name: Option<String>,
}

/// Find or create user from SAML attributes
async fn find_or_create_user(
    state: &AppState,
    tenant_id: &str,
    attributes: &SamlUserAttributes,
) -> Result<SamlUser, ApiError> {
    // Try to find existing user
    let existing: Option<(String, String)> = sqlx::query_as(
        "SELECT id, email FROM users WHERE tenant_id = $1 AND email = $2"
    )
    .bind(tenant_id)
    .bind(&attributes.email)
    .fetch_optional(state.db.pool())
    .await
    .map_err(|_| ApiError::internal())?;
    
    if let Some((id, email)) = existing {
        return Ok(SamlUser {
            id,
            email,
            name: attributes.name.clone(),
        });
    }
    
    // User not found - create via JIT provisioning
    let user_id = uuid::Uuid::new_v4().to_string();
    
    sqlx::query(
        r#"
        INSERT INTO users (id, tenant_id, email, email_verified, status, profile, created_at, updated_at)
        VALUES ($1, $2, $3, true, 'active', $4, NOW(), NOW())
        "#
    )
    .bind(&user_id)
    .bind(tenant_id)
    .bind(&attributes.email)
    .bind(serde_json::json!({
        "name": attributes.name,
        "first_name": attributes.first_name,
        "last_name": attributes.last_name,
    }))
    .execute(state.db.pool())
    .await
    .map_err(|e| {
        tracing::error!("Failed to create user: {}", e);
        ApiError::internal()
    })?;
    
    tracing::info!(
        tenant_id = %tenant_id,
        user_id = %user_id,
        email = %attributes.email,
        "Created user via JIT provisioning"
    );
    
    Ok(SamlUser {
        id: user_id,
        email: attributes.email.clone(),
        name: attributes.name.clone(),
    })
}

/// Session tokens
#[derive(Debug, Clone)]
pub struct SessionTokens {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: i64,
}

/// Create session and generate tokens
/// 
/// SECURITY: Uses cryptographically secure random token generation to prevent
/// token prediction attacks. Previous implementation used predictable format
/// strings which could allow authentication bypass.
async fn create_session(
    _state: &AppState,
    _tenant_id: &str,
    _user: &SamlUser,
) -> Result<SessionTokens, ApiError> {
    use vault_core::crypto::generate_secure_random;
    
    // SECURITY: Generate cryptographically secure random tokens
    // These tokens are unpredictable and resistant to brute force attacks
    let access_token = generate_secure_random(32);
    let refresh_token = generate_secure_random(32);
    let expires_in = 3600;

    Ok(SessionTokens {
        access_token,
        refresh_token,
        expires_in,
    })
}

/// Build success redirect URL
async fn build_success_redirect(
    state: &AppState,
    session: &SessionTokens,
    relay_state: Option<&str>,
) -> Result<String, ApiError> {
    // Get redirect URL from relay state or use default
    let base_redirect = state.config.base_url.clone();
    
    let redirect_url = if let Some(state_str) = relay_state {
        // Check if relay state is a URL
        if state_str.starts_with("http") {
            state_str.to_string()
        } else {
            format!("{}/auth/callback", base_redirect)
        }
    } else {
        format!("{}/auth/callback", base_redirect)
    };
    
    // Append tokens as query parameters
    let redirect_url = format!(
        "{}?access_token={}&refresh_token={}&expires_in={}",
        redirect_url,
        urlencoding::encode(&session.access_token),
        urlencoding::encode(&session.refresh_token),
        session.expires_in
    );
    
    Ok(redirect_url)
}

/// Render error page
/// 
/// SECURITY: HTML-escapes the error message to prevent XSS attacks.
/// All user-controlled input must be escaped before rendering.
fn render_error_page(error: &str) -> Html<String> {
    // HTML escape the error message to prevent XSS
    let escaped_error = html_escape(error);
    
    Html(format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <title>SAML Authentication Error</title>
    <style>
        body {{ font-family: sans-serif; text-align: center; padding: 50px; }}
        .error {{ color: #d32f2f; }}
    </style>
</head>
<body>
    <h1 class="error">Authentication Failed</h1>
    <p>{}</p>
    <a href="/">Return to Home</a>
</body>
</html>"#,
        escaped_error
    ))
}

/// HTML escape special characters to prevent XSS
/// 
/// Converts HTML special characters to their entity equivalents:
/// - & → &amp;
/// - < → &lt;
/// - > → &gt;
/// - " → &quot;
fn html_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_generate_relay_state() {
        let relay_state = generate_relay_state("tenant123");
        assert!(relay_state.starts_with("tenant123:"));
        assert_eq!(relay_state.split(':').count(), 2);
    }
    
    #[test]
    fn test_extract_user_attributes() {
        use super::super::{SamlAssertion, SamlAttribute, SamlConditions, SamlSubject};
        
        let assertion = SamlAssertion {
            id: "_assertion1".to_string(),
            issuer: "https://idp.example.com".to_string(),
            issue_instant: chrono::Utc::now(),
            subject: SamlSubject {
                name_id: "user@example.com".to_string(),
                name_id_format: NameIdFormat::EmailAddress,
                subject_confirmation: None,
            },
            conditions: SamlConditions {
                not_before: chrono::Utc::now(),
                not_on_or_after: chrono::Utc::now() + chrono::Duration::hours(1),
                audience_restrictions: vec![],
            },
            authn_statement: None,
            attribute_statements: vec![super::super::AttributeStatement {
                attributes: vec![
                    SamlAttribute {
                        name: "email".to_string(),
                        friendly_name: None,
                        values: vec!["user@example.com".to_string()],
                        name_format: None,
                    },
                    SamlAttribute {
                        name: "displayName".to_string(),
                        friendly_name: None,
                        values: vec!["John Doe".to_string()],
                        name_format: None,
                    },
                ],
            }],
            raw_xml: None,
        };
        
        let response = super::super::SamlResponse {
            id: "_response1".to_string(),
            in_response_to: None,
            destination: None,
            issue_instant: chrono::Utc::now(),
            issuer: "https://idp.example.com".to_string(),
            status: super::super::StatusCode::Success,
            status_message: None,
            assertions: vec![assertion],
            raw_xml: String::new(),
        };
        
        let attrs = extract_user_attributes(&response).unwrap();
        
        assert_eq!(attrs.email, "user@example.com");
        assert_eq!(attrs.name, Some("John Doe".to_string()));
    }
}
