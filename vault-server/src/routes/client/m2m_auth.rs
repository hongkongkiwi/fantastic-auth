//! M2M Authentication Routes (Client-Facing)
//!
//! Provides OAuth 2.0 client credentials token endpoint for M2M authentication.
//!
//! # Endpoint
//!
//! `POST /oauth/token` - Exchange client credentials for access token
//!
//! ## Request (application/x-www-form-urlencoded)
//! ```
//! grant_type=client_credentials&
//! client_id=CLIENT_ID&
//! client_secret=CLIENT_SECRET&
//! scope=api:read%20api:write
//! ```
//!
//! ## Response
//! ```json
//! {
//!   "access_token": "eyJhbGc...",
//!   "token_type": "Bearer",
//!   "expires_in": 3600,
//!   "scope": "api:read api:write"
//! }
//! ```
//!
//! ## Error Response
//! ```json
//! {
//!   "error": "invalid_client",
//!   "error_description": "Client authentication failed"
//! }
//! ```

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
    Form, Json, Router,
};
use serde::Deserialize;

use crate::{
    audit::{AuditAction, AuditLogger, RequestContext, ResourceType},
    m2m::{
        ClientCredentialsError, ClientCredentialsRequest, ClientCredentialsResponse,
        TokenErrorResponse,
    },
    routes::ApiError,
    state::AppState,
};

/// M2M auth routes
pub fn routes() -> Router<AppState> {
    Router::new().route("/token", post(token_endpoint))
}

/// Token endpoint supporting client credentials grant
///
/// Implements OAuth 2.0 Client Credentials Grant (RFC 6749 Section 4.4)
async fn token_endpoint(
    State(state): State<AppState>,
    Form(request): Form<ClientCredentialsRequest>,
) -> Result<Response, ApiError> {
    // Extract tenant ID from request (could be in form data, header, or inferred from client_id)
    let tenant_id = extract_tenant_id(&request);

    // Create audit context
    let context = RequestContext::from_headers(&axum::http::HeaderMap::new());
    let audit = AuditLogger::new(state.db.clone());

    // Set tenant context
    if let Err(e) = state.set_tenant_context(&tenant_id).await {
        tracing::error!("Failed to set tenant context: {}", e);
        return Err(ApiError::Internal);
    }

    // Exchange credentials for token
    match state
        .m2m_service
        .client_credentials()
        .exchange_token(request, &tenant_id)
        .await
    {
        Ok(response) => {
            // Log successful token exchange
            audit.log(
                &tenant_id,
                AuditAction::Custom("m2m.token_issued"),
                ResourceType::Token,
                "access_token",
                None,
                None,
                Some(context),
                true,
                None,
                Some(serde_json::json!({
                    "scope": response.scope,
                    "expires_in": response.expires_in,
                })),
            );

            Ok((StatusCode::OK, Json(response)).into_response())
        }
        Err(e) => {
            // Log failed token exchange
            let error_message = format!("{}", e);
            audit.log(
                &tenant_id,
                AuditAction::Custom("m2m.token_failed"),
                ResourceType::Token,
                "access_token",
                None,
                None,
                Some(context),
                false,
                Some(error_message.clone()),
                None,
            );

            tracing::warn!("Client credentials exchange failed: {}", e);

            // Convert to OAuth-compliant error response
            let (status, error_response) = map_client_credentials_error(e);
            Ok((status, Json(error_response)).into_response())
        }
    }
}

/// Extract tenant ID from the request
///
/// First tries to extract from client_id prefix, then falls back to "default"
fn extract_tenant_id(request: &ClientCredentialsRequest) -> String {
    // Client IDs have format: vault_sa_<random>
    // We could encode tenant info in the client_id, or look it up in the database
    // For now, we rely on the client_credentials service to look up by client_id
    // and return an error if the tenant doesn't match
    
    // If there's a standard way to pass tenant (like a X-Tenant-ID header),
    // we could extract it from the headers. For now, use "default".
    "default".to_string()
}

/// Map internal errors to OAuth-compliant error responses
fn map_client_credentials_error(error: ClientCredentialsError) -> (StatusCode, TokenErrorResponse) {
    match error {
        ClientCredentialsError::InvalidClient => (
            StatusCode::UNAUTHORIZED,
            TokenErrorResponse {
                error: "invalid_client".to_string(),
                error_description: Some("Client authentication failed".to_string()),
            },
        ),
        ClientCredentialsError::InvalidScope => (
            StatusCode::BAD_REQUEST,
            TokenErrorResponse {
                error: "invalid_scope".to_string(),
                error_description: Some("The requested scope is invalid or unauthorized".to_string()),
            },
        ),
        ClientCredentialsError::UnsupportedGrantType => (
            StatusCode::BAD_REQUEST,
            TokenErrorResponse {
                error: "unsupported_grant_type".to_string(),
                error_description: Some("Only client_credentials grant type is supported".to_string()),
            },
        ),
        ClientCredentialsError::AccountExpired => (
            StatusCode::UNAUTHORIZED,
            TokenErrorResponse {
                error: "invalid_client".to_string(),
                error_description: Some("Service account has expired".to_string()),
            },
        ),
        ClientCredentialsError::InvalidToken => (
            StatusCode::UNAUTHORIZED,
            TokenErrorResponse {
                error: "invalid_token".to_string(),
                error_description: Some("The access token is invalid".to_string()),
            },
        ),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            TokenErrorResponse {
                error: "server_error".to_string(),
                error_description: Some("An internal server error occurred".to_string()),
            },
        ),
    }
}

/// Alternative token endpoint that accepts JSON instead of form data
///
/// Some clients prefer JSON over form-urlencoded
#[derive(Debug, Deserialize)]
struct TokenRequestJson {
    grant_type: String,
    client_id: String,
    client_secret: String,
    scope: Option<String>,
}

impl From<TokenRequestJson> for ClientCredentialsRequest {
    fn from(req: TokenRequestJson) -> Self {
        Self {
            grant_type: req.grant_type,
            client_id: req.client_id,
            client_secret: req.client_secret,
            scope: req.scope,
        }
    }
}

/// JSON token endpoint
pub async fn token_endpoint_json(
    State(state): State<AppState>,
    Json(request): Json<TokenRequestJson>,
) -> Result<Response, ApiError> {
    token_endpoint(State(state), Form(request.into())).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_map_invalid_client_error() {
        let (status, response) = map_client_credentials_error(ClientCredentialsError::InvalidClient);
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(response.error, "invalid_client");
    }

    #[test]
    fn test_map_invalid_scope_error() {
        let (status, response) = map_client_credentials_error(ClientCredentialsError::InvalidScope);
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(response.error, "invalid_scope");
    }
}
