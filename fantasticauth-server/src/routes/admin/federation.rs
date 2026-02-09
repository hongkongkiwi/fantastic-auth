//! Admin Federation Routes
//!
//! Administrative endpoints for managing identity federation and brokering.

use axum::{
    extract::{Path, Query, State},
    routing::{delete, get, post, put},
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::db::Database;
use crate::federation::{
    FederationService, FederatedProvider, ProviderType, ProviderConfig, ProviderUpdates,
    HomeRealmDiscovery, RealmMapping, TrustManager, TrustLevel, TrustRelationship,
};
use crate::federation::trust::TrustUpdates;
use crate::federation::providers::{
    OidcProviderConfig, SamlProviderConfig, LdapProviderConfig,
};
use crate::routes::ApiError;
use crate::state::{AppState, CurrentUser};

/// Create admin federation routes
/// Mounted at `/api/v1/admin/federation`
pub fn routes() -> Router<AppState> {
    Router::new()
        // Provider management
        .route("/providers", get(list_providers).post(create_provider))
        .route("/providers/:id", get(get_provider).put(update_provider).delete(delete_provider))
        // Realm/discovery management
        .route("/realms", get(list_realm_mappings).post(create_realm_mapping))
        .route("/realms/:id", delete(delete_realm_mapping))
        // Trust relationships
        .route("/trusts", get(list_trusts).post(create_trust))
        .route("/trusts/:id", get(get_trust).put(update_trust).delete(delete_trust))
        .route("/trusts/:id/refresh", post(refresh_trust_metadata))
        // Provider discovery
        .route("/discover", post(discover_provider))
}

// ============ Request/Response Types ============

#[derive(Debug, Deserialize)]
struct CreateProviderRequest {
    name: String,
    #[serde(rename = "type")]
    provider_type: String,
    #[serde(rename = "organizationId")]
    organization_id: Option<String>,
    config: ProviderConfigInput,
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    priority: i32,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum ProviderConfigInput {
    Oidc {
        #[serde(rename = "issuer")]
        issuer: String,
        #[serde(rename = "authorizationEndpoint")]
        authorization_endpoint: String,
        #[serde(rename = "tokenEndpoint")]
        token_endpoint: String,
        #[serde(rename = "userinfoEndpoint")]
        userinfo_endpoint: String,
        #[serde(rename = "jwksUri")]
        jwks_uri: String,
        #[serde(rename = "clientId")]
        client_id: String,
        #[serde(rename = "clientSecret")]
        client_secret: Option<String>,
        #[serde(default)]
        scopes: Vec<String>,
        #[serde(default, rename = "claimsMapping")]
        claims_mapping: HashMap<String, String>,
        #[serde(default, rename = "pkceEnabled")]
        pkce_enabled: bool,
    },
    Saml {
        #[serde(rename = "entityId")]
        entity_id: String,
        #[serde(rename = "ssoUrl")]
        sso_url: String,
        #[serde(rename = "sloUrl")]
        slo_url: Option<String>,
        certificate: String,
        #[serde(rename = "nameIdFormat")]
        name_id_format: String,
        #[serde(default, rename = "attributeMappings")]
        attribute_mappings: HashMap<String, String>,
        #[serde(default, rename = "wantAssertionsSigned")]
        want_assertions_signed: bool,
    },
    Ldap {
        #[serde(rename = "serverUrl")]
        server_url: String,
        #[serde(rename = "bindDn")]
        bind_dn: String,
        #[serde(rename = "bindPassword")]
        bind_password: String,
        #[serde(rename = "baseDn")]
        base_dn: String,
        #[serde(rename = "userSearchFilter")]
        user_search_filter: String,
        #[serde(default, rename = "attributeMappings")]
        attribute_mappings: HashMap<String, String>,
        #[serde(default, rename = "useTls")]
        use_tls: bool,
    },
}

#[derive(Debug, Deserialize)]
struct UpdateProviderRequest {
    name: Option<String>,
    enabled: Option<bool>,
    priority: Option<i32>,
    config: Option<ProviderConfigInput>,
}

#[derive(Debug, Serialize)]
struct ProviderResponse {
    id: String,
    #[serde(rename = "tenantId")]
    tenant_id: String,
    #[serde(rename = "organizationId")]
    organization_id: Option<String>,
    name: String,
    #[serde(rename = "type")]
    provider_type: String,
    enabled: bool,
    priority: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    config: Option<serde_json::Value>,
    #[serde(rename = "createdAt")]
    created_at: String,
    #[serde(rename = "updatedAt")]
    updated_at: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CreateRealmMappingRequest {
    domain: String,
    #[serde(rename = "providerId")]
    provider_id: String,
    #[serde(default, rename = "isDefault")]
    is_default: bool,
}

#[derive(Debug, Serialize)]
struct RealmMappingResponse {
    id: String,
    #[serde(rename = "tenantId")]
    tenant_id: String,
    domain: String,
    #[serde(rename = "providerId")]
    provider_id: String,
    #[serde(rename = "isDefault")]
    is_default: bool,
    #[serde(rename = "createdAt")]
    created_at: String,
}

#[derive(Debug, Deserialize)]
struct CreateTrustRequest {
    #[serde(rename = "providerId")]
    provider_id: String,
    #[serde(rename = "metadataUrl")]
    metadata_url: Option<String>,
    #[serde(rename = "metadataXml")]
    metadata_xml: Option<String>,
    #[serde(rename = "certificateFingerprint")]
    certificate_fingerprint: String,
    #[serde(rename = "trustLevel")]
    trust_level: String,
    #[serde(default, rename = "autoProvisionUsers")]
    auto_provision_users: bool,
    #[serde(default, rename = "allowedClaims")]
    allowed_claims: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct UpdateTrustRequest {
    #[serde(rename = "metadataUrl")]
    metadata_url: Option<String>,
    #[serde(rename = "trustLevel")]
    trust_level: Option<String>,
    #[serde(default, rename = "autoProvisionUsers")]
    auto_provision_users: Option<bool>,
    #[serde(default, rename = "allowedClaims")]
    allowed_claims: Option<Vec<String>>,
}

#[derive(Debug, Serialize)]
struct TrustResponse {
    id: String,
    #[serde(rename = "tenantId")]
    tenant_id: String,
    #[serde(rename = "providerId")]
    provider_id: String,
    #[serde(rename = "metadataUrl")]
    metadata_url: Option<String>,
    #[serde(rename = "trustLevel")]
    trust_level: String,
    #[serde(rename = "autoProvisionUsers")]
    auto_provision_users: bool,
    #[serde(rename = "allowedClaims")]
    allowed_claims: Vec<String>,
    #[serde(rename = "createdAt")]
    created_at: String,
    #[serde(rename = "updatedAt")]
    updated_at: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DiscoverRequest {
    email: String,
}

#[derive(Debug, Serialize)]
struct DiscoverResponse {
    email: String,
    domain: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    provider: Option<ProviderInfo>,
    found: bool,
}

#[derive(Debug, Serialize)]
struct ProviderInfo {
    id: String,
    name: String,
    #[serde(rename = "type")]
    provider_type: String,
}

// ============ Handlers ============

async fn list_providers(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<serde_json::Value>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let service = FederationService::new(state.db.clone());
    let providers = service
        .list_providers(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let responses: Vec<ProviderResponse> = providers
        .into_iter()
        .map(provider_to_response)
        .collect();

    Ok(Json(serde_json::json!({
        "data": responses,
        "total": responses.len()
    })))
}

async fn create_provider(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<CreateProviderRequest>,
) -> Result<Json<ProviderResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let provider_type = ProviderType::from_str(&req.provider_type)
        .ok_or_else(|| ApiError::Validation(format!("Invalid provider type: {}", req.provider_type)))?;

    let config = provider_config_from_input(req.config)?;

    let service = FederationService::new(state.db.clone());
    let provider = service
        .create_provider(
            &current_user.tenant_id,
            req.organization_id.as_deref(),
            &req.name,
            provider_type,
            config,
            req.priority,
        )
        .await
        .map_err(|e| {
            tracing::error!("Failed to create provider: {}", e);
            ApiError::Internal
        })?;

    Ok(Json(provider_to_response(provider)))
}

async fn get_provider(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(provider_id): Path<String>,
) -> Result<Json<ProviderResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let service = FederationService::new(state.db.clone());
    let provider = service
        .get_provider(&provider_id)
        .await
        .map_err(|_| ApiError::Internal)?
        .ok_or(ApiError::NotFound)?;

    // Verify tenant ownership
    if provider.tenant_id != current_user.tenant_id {
        return Err(ApiError::Forbidden);
    }

    Ok(Json(provider_to_response(provider)))
}

async fn update_provider(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(provider_id): Path<String>,
    Json(req): Json<UpdateProviderRequest>,
) -> Result<Json<ProviderResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    // Verify provider exists and belongs to tenant
    let service = FederationService::new(state.db.clone());
    let existing = service
        .get_provider(&provider_id)
        .await
        .map_err(|_| ApiError::Internal)?
        .ok_or(ApiError::NotFound)?;

    if existing.tenant_id != current_user.tenant_id {
        return Err(ApiError::Forbidden);
    }

    let updates = ProviderUpdates {
        name: req.name,
        enabled: req.enabled,
        config: req.config.map(provider_config_from_input).transpose()?,
        priority: req.priority,
    };

    let provider = service
        .update_provider(&provider_id, updates)
        .await
        .map_err(|_| ApiError::Internal)?;

    Ok(Json(provider_to_response(provider)))
}

async fn delete_provider(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(provider_id): Path<String>,
) -> Result<(), ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    // Verify provider exists and belongs to tenant
    let service = FederationService::new(state.db.clone());
    let existing = service
        .get_provider(&provider_id)
        .await
        .map_err(|_| ApiError::Internal)?
        .ok_or(ApiError::NotFound)?;

    if existing.tenant_id != current_user.tenant_id {
        return Err(ApiError::Forbidden);
    }

    service
        .delete_provider(&provider_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    Ok(())
}

async fn list_realm_mappings(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<serde_json::Value>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let discovery = HomeRealmDiscovery::new(state.db.clone());
    let mappings = discovery
        .list_mappings(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let responses: Vec<RealmMappingResponse> = mappings
        .into_iter()
        .map(realm_mapping_to_response)
        .collect();

    Ok(Json(serde_json::json!({
        "data": responses,
        "total": responses.len()
    })))
}

async fn create_realm_mapping(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<CreateRealmMappingRequest>,
) -> Result<Json<RealmMappingResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let discovery = HomeRealmDiscovery::new(state.db.clone());
    let mapping = discovery
        .create_mapping(
            &current_user.tenant_id,
            &req.domain,
            &req.provider_id,
            req.is_default,
        )
        .await
        .map_err(|_| ApiError::Internal)?;

    Ok(Json(realm_mapping_to_response(mapping)))
}

async fn delete_realm_mapping(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(mapping_id): Path<String>,
) -> Result<(), ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let discovery = HomeRealmDiscovery::new(state.db.clone());
    discovery
        .delete_mapping(&mapping_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    Ok(())
}

async fn list_trusts(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<serde_json::Value>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let trust_manager = TrustManager::new(state.db.clone());
    let trusts = trust_manager
        .list_trusts(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let responses: Vec<TrustResponse> = trusts
        .into_iter()
        .map(trust_to_response)
        .collect();

    Ok(Json(serde_json::json!({
        "data": responses,
        "total": responses.len()
    })))
}

async fn get_trust(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(trust_id): Path<String>,
) -> Result<Json<TrustResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let trust_manager = TrustManager::new(state.db.clone());
    let trust = trust_manager
        .get_trust(&trust_id)
        .await
        .map_err(|_| ApiError::Internal)?
        .ok_or(ApiError::NotFound)?;

    if trust.tenant_id != current_user.tenant_id {
        return Err(ApiError::Forbidden);
    }

    Ok(Json(trust_to_response(trust)))
}

async fn create_trust(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<CreateTrustRequest>,
) -> Result<Json<TrustResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let trust_level = TrustLevel::from_str(&req.trust_level)
        .ok_or_else(|| ApiError::Validation(format!("Invalid trust level: {}", req.trust_level)))?;

    let trust_manager = TrustManager::new(state.db.clone());
    let trust = trust_manager
        .create_trust(
            &current_user.tenant_id,
            &req.provider_id,
            req.metadata_url.as_deref(),
            req.metadata_xml.as_deref(),
            &req.certificate_fingerprint,
            trust_level,
            req.auto_provision_users,
            req.allowed_claims,
        )
        .await
        .map_err(|_| ApiError::Internal)?;

    Ok(Json(trust_to_response(trust)))
}

async fn update_trust(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(trust_id): Path<String>,
    Json(req): Json<UpdateTrustRequest>,
) -> Result<Json<TrustResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let trust_manager = TrustManager::new(state.db.clone());
    
    // Verify trust exists and belongs to tenant
    let existing = trust_manager
        .get_trust(&trust_id)
        .await
        .map_err(|_| ApiError::Internal)?
        .ok_or(ApiError::NotFound)?;

    if existing.tenant_id != current_user.tenant_id {
        return Err(ApiError::Forbidden);
    }

    let updates = TrustUpdates {
        metadata_url: req.metadata_url,
        metadata_xml: None,
        certificate_fingerprint: None,
        trust_level: req.trust_level.and_then(|s| TrustLevel::from_str(&s)),
        auto_provision_users: req.auto_provision_users,
        allowed_claims: req.allowed_claims,
    };

    let trust = trust_manager
        .update_trust(&trust_id, updates)
        .await
        .map_err(|_| ApiError::Internal)?;

    Ok(Json(trust_to_response(trust)))
}

async fn delete_trust(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(trust_id): Path<String>,
) -> Result<(), ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let trust_manager = TrustManager::new(state.db.clone());
    trust_manager
        .delete_trust(&trust_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    Ok(())
}

async fn refresh_trust_metadata(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(trust_id): Path<String>,
) -> Result<Json<TrustResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let trust_manager = TrustManager::new(state.db.clone());
    
    // Verify trust exists and belongs to tenant
    let existing = trust_manager
        .get_trust(&trust_id)
        .await
        .map_err(|_| ApiError::Internal)?
        .ok_or(ApiError::NotFound)?;

    if existing.tenant_id != current_user.tenant_id {
        return Err(ApiError::Forbidden);
    }

    trust_manager
        .refresh_metadata(&trust_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    // Fetch updated trust
    let trust = trust_manager
        .get_trust(&trust_id)
        .await
        .map_err(|_| ApiError::Internal)?
        .ok_or(ApiError::NotFound)?;

    Ok(Json(trust_to_response(trust)))
}

async fn discover_provider(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<DiscoverRequest>,
) -> Result<Json<DiscoverResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let service = FederationService::new(state.db.clone());
    let provider = service
        .discover_provider(&req.email)
        .await
        .map_err(|_| ApiError::Internal)?;

    let domain = req.email
        .split('@')
        .nth(1)
        .unwrap_or("")
        .to_string();

    let (found, provider_info) = match provider {
        Some(p) => (
            true,
            Some(ProviderInfo {
                id: p.id,
                name: p.name,
                provider_type: p.provider_type.as_str().to_string(),
            }),
        ),
        None => (false, None),
    };

    Ok(Json(DiscoverResponse {
        email: req.email,
        domain,
        provider: provider_info,
        found,
    }))
}

// ============ Helper Functions ============

fn provider_to_response(provider: FederatedProvider) -> ProviderResponse {
    ProviderResponse {
        id: provider.id,
        tenant_id: provider.tenant_id,
        organization_id: provider.organization_id,
        name: provider.name,
        provider_type: provider.provider_type.as_str().to_string(),
        enabled: provider.enabled,
        priority: provider.priority,
        config: serde_json::to_value(&provider.config).ok(),
        created_at: provider.created_at.to_rfc3339(),
        updated_at: provider.updated_at.map(|d| d.to_rfc3339()),
    }
}

fn realm_mapping_to_response(mapping: RealmMapping) -> RealmMappingResponse {
    RealmMappingResponse {
        id: mapping.id,
        tenant_id: mapping.tenant_id,
        domain: mapping.domain,
        provider_id: mapping.provider_id,
        is_default: mapping.is_default,
        created_at: mapping.created_at.to_rfc3339(),
    }
}

fn trust_to_response(trust: TrustRelationship) -> TrustResponse {
    TrustResponse {
        id: trust.id,
        tenant_id: trust.tenant_id,
        provider_id: trust.provider_id,
        metadata_url: trust.metadata_url,
        trust_level: trust.trust_level.as_str().to_string(),
        auto_provision_users: trust.auto_provision_users,
        allowed_claims: trust.allowed_claims,
        created_at: trust.created_at.to_rfc3339(),
        updated_at: trust.updated_at.map(|d| d.to_rfc3339()),
    }
}

fn provider_config_from_input(input: ProviderConfigInput) -> Result<ProviderConfig, ApiError> {
    match input {
        ProviderConfigInput::Oidc {
            issuer,
            authorization_endpoint,
            token_endpoint,
            userinfo_endpoint,
            jwks_uri,
            client_id,
            client_secret,
            scopes,
            claims_mapping,
            pkce_enabled,
        } => Ok(ProviderConfig::Oidc(OidcProviderConfig {
            issuer,
            authorization_endpoint,
            token_endpoint,
            userinfo_endpoint,
            jwks_uri,
            client_id,
            client_secret,
            scopes,
            claims_mapping,
            pkce_enabled,
        })),
        ProviderConfigInput::Saml {
            entity_id,
            sso_url,
            slo_url,
            certificate,
            name_id_format,
            attribute_mappings,
            want_assertions_signed,
        } => Ok(ProviderConfig::Saml(SamlProviderConfig {
            entity_id,
            sso_url,
            slo_url,
            certificate,
            name_id_format,
            attribute_mappings,
            want_assertions_signed,
            want_assertions_encrypted: false,
            sp_private_key: None,
            sp_certificate: None,
        })),
        ProviderConfigInput::Ldap {
            server_url,
            bind_dn,
            bind_password,
            base_dn,
            user_search_filter,
            attribute_mappings,
            use_tls,
        } => Ok(ProviderConfig::Ldap(LdapProviderConfig {
            server_url,
            bind_dn,
            bind_password,
            base_dn,
            user_search_filter,
            attribute_mappings,
            use_tls,
            tls_verify: true,
            tls_cert: None,
        })),
    }
}
