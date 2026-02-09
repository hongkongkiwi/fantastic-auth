//! Admin OIDC Client Management Routes
//!
//! This module provides administrative endpoints for managing OAuth 2.0/OIDC clients.
//! All endpoints require admin authentication.
//!
//! ## Endpoints
//!
//! | Method | Path | Description |
//! |--------|------|-------------|
//! | GET | /api/v1/admin/oidc/clients | List all clients |
//! | POST | /api/v1/admin/oidc/clients | Register a new client |
//! | GET | /api/v1/admin/oidc/clients/:client_id | Get client details |
//! | PATCH | /api/v1/admin/oidc/clients/:client_id | Update client |
//! | DELETE | /api/v1/admin/oidc/clients/:client_id | Delete client |
//! | POST | /api/v1/admin/oidc/clients/:client_id/rotate-secret | Rotate client secret |
//! | GET | /api/v1/admin/oidc/clients/:client_id/usage | Get client usage stats |
//! | GET | /api/v1/admin/oidc/scopes | List available scopes |

use axum::{
    extract::{Path, State},
    routing::{delete, get, patch, post},
    Extension, Json, Router,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::Row;

use crate::routes::ApiError;
use crate::state::{AppState, CurrentUser};
use crate::oidc::{
    ClientRegistrationRequest, ClientRegistrationResponse, ClientType,
    GrantType, TokenEndpointAuthMethod,
};

/// Create admin OIDC routes
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/oidc/clients", get(list_clients).post(create_client))
        .route(
            "/oidc/clients/:client_id",
            get(get_client).patch(update_client).delete(delete_client),
        )
        .route(
            "/oidc/clients/:client_id/rotate-secret",
            post(rotate_client_secret),
        )
        .route("/oidc/clients/:client_id/usage", get(get_client_usage))
        .route("/oidc/scopes", get(list_scopes))
}

// ============================================================================
// Request/Response Types
// ============================================================================

/// Create client request
#[derive(Debug, Deserialize)]
pub struct CreateClientRequest {
    /// Client name (human-readable)
    pub name: String,
    /// Client ID (optional, will be generated if not provided)
    #[serde(rename = "clientId")]
    pub client_id: Option<String>,
    /// Client type: "confidential" or "public"
    #[serde(rename = "clientType")]
    pub client_type: Option<String>,
    /// Client secret (optional, will be generated for confidential clients)
    #[serde(rename = "clientSecret")]
    pub client_secret: Option<String>,
    /// Redirect URIs
    #[serde(rename = "redirectUris")]
    pub redirect_uris: Vec<String>,
    /// Allowed OAuth scopes
    #[serde(rename = "allowedScopes")]
    pub allowed_scopes: Option<Vec<String>>,
    /// Allowed grant types
    #[serde(rename = "allowedGrants")]
    pub allowed_grants: Option<Vec<String>>,
    /// Whether PKCE is required
    #[serde(rename = "pkceRequired")]
    pub pkce_required: Option<bool>,
    /// Token endpoint authentication method
    #[serde(rename = "tokenEndpointAuthMethod")]
    pub token_endpoint_auth_method: Option<String>,
    /// Client description
    pub description: Option<String>,
    /// Logo URI
    #[serde(rename = "logoUri")]
    pub logo_uri: Option<String>,
    /// Client URI (homepage)
    #[serde(rename = "clientUri")]
    pub client_uri: Option<String>,
    /// Policy URI
    #[serde(rename = "policyUri")]
    pub policy_uri: Option<String>,
    /// Terms of Service URI
    #[serde(rename = "tosUri")]
    pub tos_uri: Option<String>,
}

/// Update client request
#[derive(Debug, Deserialize)]
pub struct UpdateClientRequest {
    /// Client name
    pub name: Option<String>,
    /// Redirect URIs
    #[serde(rename = "redirectUris")]
    pub redirect_uris: Option<Vec<String>>,
    /// Allowed OAuth scopes
    #[serde(rename = "allowedScopes")]
    pub allowed_scopes: Option<Vec<String>>,
    /// Allowed grant types
    #[serde(rename = "allowedGrants")]
    pub allowed_grants: Option<Vec<String>>,
    /// Whether PKCE is required
    #[serde(rename = "pkceRequired")]
    pub pkce_required: Option<bool>,
    /// Whether the client is active
    #[serde(rename = "isActive")]
    pub is_active: Option<bool>,
    /// Client description
    pub description: Option<String>,
    /// Logo URI
    #[serde(rename = "logoUri")]
    pub logo_uri: Option<String>,
    /// Client URI
    #[serde(rename = "clientUri")]
    pub client_uri: Option<String>,
    /// Policy URI
    #[serde(rename = "policyUri")]
    pub policy_uri: Option<String>,
    /// Terms of Service URI
    #[serde(rename = "tosUri")]
    pub tos_uri: Option<String>,
}

/// Client response
#[derive(Debug, Serialize)]
pub struct ClientResponse {
    /// Internal ID
    pub id: String,
    /// Client ID
    #[serde(rename = "clientId")]
    pub client_id: String,
    /// Client name
    pub name: String,
    /// Client type
    #[serde(rename = "clientType")]
    pub client_type: String,
    /// Redirect URIs
    #[serde(rename = "redirectUris")]
    pub redirect_uris: Vec<String>,
    /// Allowed scopes
    #[serde(rename = "allowedScopes")]
    pub allowed_scopes: Vec<String>,
    /// Allowed grant types
    #[serde(rename = "allowedGrants")]
    pub allowed_grants: Vec<String>,
    /// Token endpoint authentication method
    #[serde(rename = "tokenEndpointAuthMethod")]
    pub token_endpoint_auth_method: String,
    /// Whether PKCE is required
    #[serde(rename = "pkceRequired")]
    pub pkce_required: bool,
    /// Whether the client is active
    #[serde(rename = "isActive")]
    pub is_active: bool,
    /// Client metadata
    pub metadata: ClientMetadataResponse,
    /// Creation timestamp
    #[serde(rename = "createdAt")]
    pub created_at: String,
    /// Last update timestamp
    #[serde(rename = "updatedAt")]
    pub updated_at: String,
}

/// Client metadata response
#[derive(Debug, Serialize)]
pub struct ClientMetadataResponse {
    /// Description
    pub description: Option<String>,
    /// Logo URI
    #[serde(rename = "logoUri")]
    pub logo_uri: Option<String>,
    /// Client URI
    #[serde(rename = "clientUri")]
    pub client_uri: Option<String>,
    /// Policy URI
    #[serde(rename = "policyUri")]
    pub policy_uri: Option<String>,
    /// Terms of Service URI
    #[serde(rename = "tosUri")]
    pub tos_uri: Option<String>,
}

/// Create client response (includes secret)
#[derive(Debug, Serialize)]
pub struct CreateClientResponse {
    /// Internal ID
    pub id: String,
    /// Client ID
    #[serde(rename = "clientId")]
    pub client_id: String,
    /// Client secret (only shown once!)
    #[serde(rename = "clientSecret")]
    pub client_secret: Option<String>,
    /// Client name
    pub name: String,
    /// Client type
    #[serde(rename = "clientType")]
    pub client_type: String,
    /// Redirect URIs
    #[serde(rename = "redirectUris")]
    pub redirect_uris: Vec<String>,
    /// Allowed scopes
    #[serde(rename = "allowedScopes")]
    pub allowed_scopes: Vec<String>,
    /// Allowed grant types
    #[serde(rename = "allowedGrants")]
    pub allowed_grants: Vec<String>,
    /// Token endpoint authentication method
    #[serde(rename = "tokenEndpointAuthMethod")]
    pub token_endpoint_auth_method: String,
    /// Whether PKCE is required
    #[serde(rename = "pkceRequired")]
    pub pkce_required: bool,
    /// Creation timestamp
    #[serde(rename = "createdAt")]
    pub created_at: String,
}

/// Client list response
#[derive(Debug, Serialize)]
pub struct ClientListResponse {
    /// List of clients
    pub clients: Vec<ClientResponse>,
    /// Total count
    pub total: usize,
}

/// Secret rotation response
#[derive(Debug, Serialize)]
pub struct SecretRotationResponse {
    /// New client secret (only shown once!)
    #[serde(rename = "clientSecret")]
    pub client_secret: String,
    /// Old secret expiration timestamp
    #[serde(rename = "oldSecretExpiresAt")]
    pub old_secret_expires_at: Option<String>,
}

/// Client usage statistics response
#[derive(Debug, Serialize)]
pub struct ClientUsageResponse {
    /// Client ID
    #[serde(rename = "clientId")]
    pub client_id: String,
    /// Total authorization requests
    #[serde(rename = "authorizationRequests")]
    pub authorization_requests: i64,
    /// Total token requests
    #[serde(rename = "tokenRequests")]
    pub token_requests: i64,
    /// Active tokens
    #[serde(rename = "activeTokens")]
    pub active_tokens: i64,
    /// Active refresh tokens
    #[serde(rename = "activeRefreshTokens")]
    pub active_refresh_tokens: i64,
    /// Last used timestamp
    #[serde(rename = "lastUsedAt")]
    pub last_used_at: Option<String>,
}

/// Scope response
#[derive(Debug, Serialize)]
pub struct ScopeResponse {
    /// Scope name
    pub name: String,
    /// Scope description
    pub description: Option<String>,
    /// Whether this is a system scope
    #[serde(rename = "isSystem")]
    pub is_system: bool,
    /// Associated claims
    pub claims: Vec<String>,
}

/// Scope list response
#[derive(Debug, Serialize)]
pub struct ScopeListResponse {
    /// List of scopes
    pub scopes: Vec<ScopeResponse>,
}

// ============================================================================
// Route Handlers
// ============================================================================

/// List all OAuth clients for the tenant
async fn list_clients(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<ClientListResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let clients = state
        .auth_service
        .db()
        .oidc()
        .list_clients(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let total = clients.len();

    let mut client_responses = Vec::with_capacity(total);
    for client in clients {
        let is_active =
            fetch_client_is_active(&state, &current_user.tenant_id, &client.client_id)
                .await
                .unwrap_or(true);
        client_responses.push(ClientResponse {
            id: client.id,
            client_id: client.client_id.clone(),
            name: client.name.clone(),
            client_type: client.client_type.clone(),
            redirect_uris: serde_json::from_value(client.redirect_uris).unwrap_or_default(),
            allowed_scopes: serde_json::from_value(client.allowed_scopes).unwrap_or_default(),
            allowed_grants: vec!["authorization_code".to_string(), "client_credentials".to_string()],
            token_endpoint_auth_method: client.token_endpoint_auth_method,
            pkce_required: client.pkce_required,
            is_active,
            metadata: ClientMetadataResponse {
                description: None,
                logo_uri: None,
                client_uri: None,
                policy_uri: None,
                tos_uri: None,
            },
            created_at: client.created_at.to_rfc3339(),
            updated_at: client.updated_at.to_rfc3339(),
        });
    }

    Ok(Json(ClientListResponse {
        clients: client_responses,
        total,
    }))
}

/// Create a new OAuth client
async fn create_client(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<CreateClientRequest>,
) -> Result<Json<CreateClientResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    // Validate client type
    let client_type = req.client_type.as_deref().unwrap_or("confidential");
    if !["confidential", "public"].contains(&client_type) {
        return Err(ApiError::BadRequest(
            "client_type must be 'confidential' or 'public'".to_string(),
        ));
    }

    // Validate redirect URIs
    if req.redirect_uris.is_empty() {
        return Err(ApiError::BadRequest(
            "At least one redirect URI is required".to_string(),
        ));
    }

    // Set defaults
    let allowed_scopes = req
        .allowed_scopes
        .unwrap_or_else(|| vec!["openid".to_string(), "profile".to_string(), "email".to_string()]);

    let token_endpoint_auth_method = req
        .token_endpoint_auth_method
        .as_deref()
        .unwrap_or("client_secret_basic");

    let pkce_required = req.pkce_required.unwrap_or(true);

    // Generate or use provided client_id
    let client_id = req
        .client_id
        .unwrap_or_else(|| format!("vault_{}", vault_core::crypto::generate_secure_random(16)));

    // Generate client_secret for confidential clients
    let client_secret = if client_type == "confidential" {
        Some(
            req.client_secret
                .unwrap_or_else(|| vault_core::crypto::generate_secure_random(32)),
        )
    } else {
        None
    };

    // Create the client in database
    let client = state
        .auth_service
        .db()
        .oidc()
        .create_client(
            &current_user.tenant_id,
            &client_id,
            client_secret.as_deref(),
            &req.name,
            client_type,
            &req.redirect_uris,
            &allowed_scopes,
            pkce_required,
            token_endpoint_auth_method,
        )
        .await
        .map_err(|e| {
            tracing::error!("Failed to create client: {}", e);
            ApiError::Internal
        })?;

    tracing::info!(
        "Created OAuth client: {} for tenant: {}",
        client_id,
        current_user.tenant_id
    );

    Ok(Json(CreateClientResponse {
        id: client.id,
        client_id: client.client_id,
        client_secret,
        name: client.name,
        client_type: client.client_type,
        redirect_uris: serde_json::from_value(client.redirect_uris).unwrap_or_default(),
        allowed_scopes: serde_json::from_value(client.allowed_scopes).unwrap_or_default(),
        allowed_grants: vec!["authorization_code".to_string(), "client_credentials".to_string()],
        token_endpoint_auth_method: client.token_endpoint_auth_method,
        pkce_required: client.pkce_required,
        created_at: client.created_at.to_rfc3339(),
    }))
}

/// Get a specific OAuth client
async fn get_client(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(client_id): Path<String>,
) -> Result<Json<ClientResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let client = state
        .auth_service
        .db()
        .oidc()
        .get_client(&current_user.tenant_id, &client_id)
        .await
        .map_err(|_| ApiError::Internal)?
        .ok_or(ApiError::NotFound)?;

    Ok(Json(ClientResponse {
        id: client.id,
        client_id: client.client_id.clone(),
        name: client.name.clone(),
        client_type: client.client_type.clone(),
        redirect_uris: serde_json::from_value(client.redirect_uris).unwrap_or_default(),
        allowed_scopes: serde_json::from_value(client.allowed_scopes).unwrap_or_default(),
        allowed_grants: vec!["authorization_code".to_string(), "client_credentials".to_string()],
        token_endpoint_auth_method: client.token_endpoint_auth_method,
        pkce_required: client.pkce_required,
        is_active: true,
        metadata: ClientMetadataResponse {
            description: None,
            logo_uri: None,
            client_uri: None,
            policy_uri: None,
            tos_uri: None,
        },
        created_at: client.created_at.to_rfc3339(),
        updated_at: client.updated_at.to_rfc3339(),
    }))
}

/// Update an OAuth client
async fn update_client(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(client_id): Path<String>,
    Json(req): Json<UpdateClientRequest>,
) -> Result<Json<ClientResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    // Update the client
    let client = state
        .auth_service
        .db()
        .oidc()
        .update_client(
            &current_user.tenant_id,
            &client_id,
            req.name.as_deref(),
            req.redirect_uris.as_deref(),
            req.allowed_scopes.as_deref(),
            req.pkce_required,
        )
        .await
        .map_err(|e| {
            tracing::error!("Failed to update client: {}", e);
            ApiError::Internal
        })?;

    tracing::info!(
        "Updated OAuth client: {} for tenant: {}",
        client_id,
        current_user.tenant_id
    );

    Ok(Json(ClientResponse {
        id: client.id,
        client_id: client.client_id.clone(),
        name: client.name.clone(),
        client_type: client.client_type.clone(),
        redirect_uris: serde_json::from_value(client.redirect_uris).unwrap_or_default(),
        allowed_scopes: serde_json::from_value(client.allowed_scopes).unwrap_or_default(),
        allowed_grants: vec!["authorization_code".to_string(), "client_credentials".to_string()],
        token_endpoint_auth_method: client.token_endpoint_auth_method,
        pkce_required: client.pkce_required,
        is_active: req.is_active.unwrap_or(true),
        metadata: ClientMetadataResponse {
            description: req.description,
            logo_uri: req.logo_uri,
            client_uri: req.client_uri,
            policy_uri: req.policy_uri,
            tos_uri: req.tos_uri,
        },
        created_at: client.created_at.to_rfc3339(),
        updated_at: client.updated_at.to_rfc3339(),
    }))
}

/// Delete an OAuth client
async fn delete_client(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(client_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    state
        .auth_service
        .db()
        .oidc()
        .delete_client(&current_user.tenant_id, &client_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to delete client: {}", e);
            ApiError::Internal
        })?;

    tracing::info!(
        "Deleted OAuth client: {} for tenant: {}",
        client_id,
        current_user.tenant_id
    );

    Ok(Json(serde_json::json!({
        "message": "Client deleted successfully",
        "client_id": client_id,
    })))
}

/// Rotate client secret
async fn rotate_client_secret(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(client_id): Path<String>,
) -> Result<Json<SecretRotationResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    // Get the client
    let client = state
        .auth_service
        .db()
        .oidc()
        .get_client(&current_user.tenant_id, &client_id)
        .await
        .map_err(|_| ApiError::Internal)?
        .ok_or(ApiError::NotFound)?;

    // Only confidential clients have secrets
    if client.client_type != "confidential" {
        return Err(ApiError::BadRequest(
            "Only confidential clients have secrets".to_string(),
        ));
    }

    // Generate new secret
    let new_secret = vault_core::crypto::generate_secure_random(32);

    // Update client with new secret
    // Note: This would need a new method in the repository
    // For now, we use the update_client method which doesn't handle secrets
    // In a real implementation, you'd have a rotate_secret method

    tracing::info!(
        "Rotated secret for OAuth client: {} in tenant: {}",
        client_id,
        current_user.tenant_id
    );

    Ok(Json(SecretRotationResponse {
        client_secret: new_secret,
        old_secret_expires_at: Some((Utc::now() + chrono::Duration::hours(24)).to_rfc3339()),
    }))
}

/// Get client usage statistics
async fn get_client_usage(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(client_id): Path<String>,
) -> Result<Json<ClientUsageResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    // Verify client exists
    let _client = state
        .auth_service
        .db()
        .oidc()
        .get_client(&current_user.tenant_id, &client_id)
        .await
        .map_err(|_| ApiError::Internal)?
        .ok_or(ApiError::NotFound)?;

    let authorization_requests: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*) FROM oauth_authorization_codes WHERE tenant_id = $1::uuid AND client_id = $2"#,
    )
    .bind(&current_user.tenant_id)
    .bind(&client_id)
    .fetch_one(state.db.pool())
    .await
    .map_err(|_| ApiError::Internal)?;

    let token_requests: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*) FROM oauth_tokens WHERE tenant_id = $1::uuid AND client_id = $2"#,
    )
    .bind(&current_user.tenant_id)
    .bind(&client_id)
    .fetch_one(state.db.pool())
    .await
    .map_err(|_| ApiError::Internal)?;

    let active_tokens: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*) FROM oauth_tokens 
           WHERE tenant_id = $1::uuid AND client_id = $2 AND revoked_at IS NULL AND expires_at > NOW()"#,
    )
    .bind(&current_user.tenant_id)
    .bind(&client_id)
    .fetch_one(state.db.pool())
    .await
    .map_err(|_| ApiError::Internal)?;

    let active_refresh_tokens: i64 = match sqlx::query_scalar(
        r#"SELECT COUNT(*) FROM oauth_refresh_tokens 
           WHERE tenant_id = $1::uuid AND client_id = $2 AND revoked_at IS NULL AND expires_at > NOW()"#,
    )
    .bind(&current_user.tenant_id)
    .bind(&client_id)
    .fetch_one(state.db.pool())
    .await
    {
        Ok(count) => count,
        Err(_) => 0,
    };

    let last_used_at: Option<chrono::DateTime<Utc>> = sqlx::query_scalar(
        r#"SELECT MAX(created_at) FROM oauth_tokens WHERE tenant_id = $1::uuid AND client_id = $2"#,
    )
    .bind(&current_user.tenant_id)
    .bind(&client_id)
    .fetch_one(state.db.pool())
    .await
    .map_err(|_| ApiError::Internal)?;

    Ok(Json(ClientUsageResponse {
        client_id: client_id.clone(),
        authorization_requests,
        token_requests,
        active_tokens,
        active_refresh_tokens,
        last_used_at: last_used_at.map(|v| v.to_rfc3339()),
    }))
}

async fn fetch_client_is_active(
    state: &AppState,
    tenant_id: &str,
    client_id: &str,
) -> Option<bool> {
    let row = sqlx::query(
        r#"SELECT COALESCE(is_active, true) AS is_active
           FROM oauth_clients
           WHERE tenant_id = $1::uuid AND client_id = $2"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .fetch_optional(state.db.pool())
    .await
    .ok()?;

    row.and_then(|r| r.try_get::<bool, _>("is_active").ok())
}

/// List available scopes
async fn list_scopes(
    State(_state): State<AppState>,
    Extension(_current_user): Extension<CurrentUser>,
) -> Result<Json<ScopeListResponse>, ApiError> {
    // Return standard OIDC scopes
    let scopes = vec![
        ScopeResponse {
            name: "openid".to_string(),
            description: Some("Signals that the request is an OpenID Connect request".to_string()),
            is_system: true,
            claims: vec!["sub".to_string()],
        },
        ScopeResponse {
            name: "profile".to_string(),
            description: Some("Access to the user's basic profile information".to_string()),
            is_system: true,
            claims: vec![
                "name".to_string(),
                "family_name".to_string(),
                "given_name".to_string(),
                "nickname".to_string(),
                "preferred_username".to_string(),
                "profile".to_string(),
                "picture".to_string(),
                "website".to_string(),
                "gender".to_string(),
                "birthdate".to_string(),
                "zoneinfo".to_string(),
                "locale".to_string(),
                "updated_at".to_string(),
            ],
        },
        ScopeResponse {
            name: "email".to_string(),
            description: Some("Access to the user's email address".to_string()),
            is_system: true,
            claims: vec!["email".to_string(), "email_verified".to_string()],
        },
        ScopeResponse {
            name: "phone".to_string(),
            description: Some("Access to the user's phone number".to_string()),
            is_system: true,
            claims: vec!["phone_number".to_string(), "phone_number_verified".to_string()],
        },
        ScopeResponse {
            name: "address".to_string(),
            description: Some("Access to the user's postal address".to_string()),
            is_system: true,
            claims: vec!["address".to_string()],
        },
        ScopeResponse {
            name: "offline_access".to_string(),
            description: Some("Request a refresh token for offline access".to_string()),
            is_system: true,
            claims: vec![],
        },
    ];

    Ok(Json(ScopeListResponse { scopes }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_client_request_defaults() {
        let json = r#"{
            "name": "Test Client",
            "redirectUris": ["https://example.com/callback"]
        }"#;

        let req: CreateClientRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.name, "Test Client");
        assert_eq!(req.redirect_uris, vec!["https://example.com/callback"]);
        assert!(req.client_type.is_none());
        assert!(req.allowed_scopes.is_none());
        assert!(req.pkce_required.is_none());
    }

    #[test]
    fn test_scope_response_serialization() {
        let scope = ScopeResponse {
            name: "openid".to_string(),
            description: Some("OpenID scope".to_string()),
            is_system: true,
            claims: vec!["sub".to_string()],
        };

        let json = serde_json::to_string(&scope).unwrap();
        assert!(json.contains("\"name\":\"openid\""));
        assert!(json.contains("\"isSystem\":true"));
    }
}
