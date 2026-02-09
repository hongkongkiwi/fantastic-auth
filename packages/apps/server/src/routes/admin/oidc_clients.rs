//! Admin OIDC Client Management Routes

use axum::{
    extract::{Path, State},
    routing::{delete, get, patch, post},
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};

use crate::routes::ApiError;
use crate::state::{AppState, CurrentUser};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/oidc/clients", get(list_clients).post(create_client))
        .route(
            "/oidc/clients/:client_id",
            get(get_client).patch(update_client).delete(delete_client),
        )
}

#[derive(Debug, Deserialize)]
struct CreateClientRequest {
    name: String,
    #[serde(rename = "clientId")]
    client_id: String,
    #[serde(rename = "clientSecret")]
    client_secret: Option<String>,
    #[serde(rename = "clientType")]
    client_type: Option<String>,
    #[serde(rename = "redirectUris")]
    redirect_uris: Vec<String>,
    #[serde(rename = "allowedScopes")]
    allowed_scopes: Option<Vec<String>>,
    #[serde(rename = "pkceRequired")]
    pkce_required: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct UpdateClientRequest {
    name: Option<String>,
    #[serde(rename = "redirectUris")]
    redirect_uris: Option<Vec<String>>,
    #[serde(rename = "allowedScopes")]
    allowed_scopes: Option<Vec<String>>,
    #[serde(rename = "pkceRequired")]
    pkce_required: Option<bool>,
}

#[derive(Debug, Serialize)]
struct ClientResponse {
    id: String,
    #[serde(rename = "clientId")]
    client_id: String,
    name: String,
    #[serde(rename = "clientType")]
    client_type: String,
    #[serde(rename = "redirectUris")]
    redirect_uris: Vec<String>,
    #[serde(rename = "allowedScopes")]
    allowed_scopes: Vec<String>,
    #[serde(rename = "pkceRequired")]
    pkce_required: bool,
    #[serde(rename = "createdAt")]
    created_at: String,
}

async fn list_clients(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<Vec<ClientResponse>>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    let clients = state
        .auth_service
        .db()
        .oidc()
        .list_clients(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    let responses = clients
        .into_iter()
        .map(|c| ClientResponse {
            id: c.id,
            client_id: c.client_id,
            name: c.name,
            client_type: c.client_type,
            redirect_uris: serde_json::from_value(c.redirect_uris).unwrap_or_default(),
            allowed_scopes: serde_json::from_value(c.allowed_scopes).unwrap_or_default(),
            pkce_required: c.pkce_required,
            created_at: c.created_at.to_rfc3339(),
        })
        .collect();

    Ok(Json(responses))
}

async fn create_client(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<CreateClientRequest>,
) -> Result<Json<ClientResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    let client_type = req.client_type.unwrap_or_else(|| "confidential".to_string());
    let allowed_scopes = req
        .allowed_scopes
        .unwrap_or_else(|| vec!["openid".to_string(), "profile".to_string(), "email".to_string()]);

    let client = state
        .auth_service
        .db()
        .oidc()
        .create_client(
            &current_user.tenant_id,
            &req.client_id,
            req.client_secret.as_deref(),
            &req.name,
            &client_type,
            &req.redirect_uris,
            &allowed_scopes,
            req.pkce_required.unwrap_or(true),
            "client_secret_basic",
        )
        .await
        .map_err(|_| ApiError::internal())?;

    Ok(Json(ClientResponse {
        id: client.id,
        client_id: client.client_id,
        name: client.name,
        client_type: client.client_type,
        redirect_uris: serde_json::from_value(client.redirect_uris).unwrap_or_default(),
        allowed_scopes: serde_json::from_value(client.allowed_scopes).unwrap_or_default(),
        pkce_required: client.pkce_required,
        created_at: client.created_at.to_rfc3339(),
    }))
}

async fn get_client(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(client_id): Path<String>,
) -> Result<Json<ClientResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    let client = state
        .auth_service
        .db()
        .oidc()
        .get_client(&current_user.tenant_id, &client_id)
        .await
        .map_err(|_| ApiError::internal())?
        .ok_or(ApiError::NotFound)?;

    Ok(Json(ClientResponse {
        id: client.id,
        client_id: client.client_id,
        name: client.name,
        client_type: client.client_type,
        redirect_uris: serde_json::from_value(client.redirect_uris).unwrap_or_default(),
        allowed_scopes: serde_json::from_value(client.allowed_scopes).unwrap_or_default(),
        pkce_required: client.pkce_required,
        created_at: client.created_at.to_rfc3339(),
    }))
}

async fn update_client(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(client_id): Path<String>,
    Json(req): Json<UpdateClientRequest>,
) -> Result<Json<ClientResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

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
        .map_err(|_| ApiError::internal())?;

    Ok(Json(ClientResponse {
        id: client.id,
        client_id: client.client_id,
        name: client.name,
        client_type: client.client_type,
        redirect_uris: serde_json::from_value(client.redirect_uris).unwrap_or_default(),
        allowed_scopes: serde_json::from_value(client.allowed_scopes).unwrap_or_default(),
        pkce_required: client.pkce_required,
        created_at: client.created_at.to_rfc3339(),
    }))
}

async fn delete_client(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(client_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    state
        .auth_service
        .db()
        .oidc()
        .delete_client(&current_user.tenant_id, &client_id)
        .await
        .map_err(|_| ApiError::internal())?;

    Ok(Json(serde_json::json!({"message": "Client deleted"})))
}
