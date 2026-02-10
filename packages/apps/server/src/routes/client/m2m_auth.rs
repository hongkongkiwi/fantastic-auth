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

use crate::{
    audit::{AuditAction, AuditLogger, RequestContext, ResourceType},
    m2m::{
        ClientCredentialsError, ClientCredentialsRequest,
        TokenErrorResponse,
    },
    routes::ApiError,
    state::AppState,
};
use vault_core::db::{with_request_context, RequestContext as DbRequestContext};

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
    // Resolve tenant from the authoritative client_id -> service_account mapping.
    let tenant_id = match resolve_tenant_id_by_client_id(&state, &request.client_id).await {
        Ok(tenant_id) => tenant_id,
        Err(sqlx::Error::RowNotFound) => {
            let (status, error_response) =
                map_client_credentials_error(ClientCredentialsError::InvalidClient);
            return Ok((status, Json(error_response)).into_response());
        }
        Err(e) => {
            tracing::error!("Failed to resolve tenant for client_id: {}", e);
            let (status, error_response) =
                map_client_credentials_error(ClientCredentialsError::Database(e.to_string()));
            return Ok((status, Json(error_response)).into_response());
        }
    };

    let ctx = DbRequestContext {
        tenant_id: Some(tenant_id.clone()),
        user_id: None,
        role: Some("service".to_string()),
    };

    with_request_context(ctx, async move {
        // Create audit context
        let context = RequestContext::from_headers(&axum::http::HeaderMap::new());
        let audit = AuditLogger::new(state.db.clone());

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
    })
    .await
}

/// Resolve tenant ID from client_id using service account records.
async fn resolve_tenant_id_by_client_id(
    state: &AppState,
    client_id: &str,
) -> Result<String, sqlx::Error> {
    sqlx::query_scalar(
        r#"SELECT tenant_id::text
           FROM service_accounts
           WHERE client_id = $1
           LIMIT 1"#,
    )
    .bind(client_id)
    .fetch_one(state.db.pool())
    .await
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
        ClientCredentialsError::Database(_) | ClientCredentialsError::TokenGeneration(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            TokenErrorResponse {
                error: "server_error".to_string(),
                error_description: Some("An internal server error occurred".to_string()),
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
