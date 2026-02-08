//! M2M Authentication Middleware
//!
//! Handles authentication for service accounts via:
//! - API key in Authorization header: `Authorization: Bearer <api_key>`
//! - M2M JWT access token in Authorization header
//!
//! Extracts and validates the credential, then sets the service account
//! context in the request extensions for downstream handlers.

use axum::{
    extract::{ConnectInfo, Request, State},
    http::{header, StatusCode},
    middleware::Next,
    response::Response,
};
use std::net::SocketAddr;

use crate::{
    audit::{AuditAction, AuditLogger, RequestContext, ResourceType},
    m2m::{ApiKeyError, AuthenticationMethod, ClientCredentialsError, ServiceAccountContext},
    state::AppState,
};

/// Extract credential from Authorization header
fn extract_credential(request: &Request) -> Option<&str> {
    let auth_header = request
        .headers()
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?;

    // Check for Bearer token
    if auth_header.starts_with("Bearer ") {
        Some(&auth_header[7..])
    } else {
        None
    }
}

/// Extract tenant ID from request headers
fn extract_tenant_id(request: &Request) -> String {
    request
        .headers()
        .get("X-Tenant-ID")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("default")
        .to_string()
}

/// Check if a token is an M2M API key
fn is_api_key(token: &str) -> bool {
    token.starts_with(crate::m2m::API_KEY_PREFIX)
}

/// M2M authentication middleware
///
/// Validates API keys or M2M access tokens from the Authorization header.
/// Sets ServiceAccountContext in request extensions if valid.
pub async fn m2m_auth_middleware(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let tenant_id = extract_tenant_id(&request);
    let context = RequestContext::from_request(request.headers(), Some(&ConnectInfo(addr)));
    let audit = AuditLogger::new(state.db.clone());

    // Extract credential
    let credential = match extract_credential(&request) {
        Some(c) => c,
        None => {
            // No credential provided
            audit.log(
                &tenant_id,
                AuditAction::Custom("m2m.auth_failed"),
                ResourceType::Token,
                "unknown",
                None,
                None,
                Some(context),
                false,
                Some("No M2M credential provided".to_string()),
                None,
            );
            return Err(StatusCode::UNAUTHORIZED);
        }
    };

    // Determine credential type and validate
    let service_context = if is_api_key(credential) {
        // Validate API key
        match validate_api_key(&state, &tenant_id, credential).await {
            Ok(ctx) => ctx,
            Err(e) => {
                tracing::warn!("M2M API key validation failed: {}", e);
                audit.log(
                    &tenant_id,
                    AuditAction::Custom("m2m.auth_failed"),
                    ResourceType::Token,
                    "api_key",
                    None,
                    None,
                    Some(context),
                    false,
                    Some(format!("API key validation failed: {}", e)),
                    None,
                );
                return Err(StatusCode::UNAUTHORIZED);
            }
        }
    } else {
        // Validate JWT access token
        match validate_m2m_token(&state, credential).await {
            Ok(ctx) => ctx,
            Err(e) => {
                tracing::warn!("M2M token validation failed: {}", e);
                audit.log(
                    &tenant_id,
                    AuditAction::Custom("m2m.auth_failed"),
                    ResourceType::Token,
                    "access_token",
                    None,
                    None,
                    Some(context),
                    false,
                    Some(format!("Token validation failed: {}", e)),
                    None,
                );
                return Err(StatusCode::UNAUTHORIZED);
            }
        }
    };

    // Check rate limits if configured
    if let Err(_) = check_rate_limit(&state, &service_context).await {
        audit.log(
            &tenant_id,
            AuditAction::Custom("m2m.rate_limit_exceeded"),
            ResourceType::Token,
            &service_context.service_account_id,
            None,
            None,
            Some(context),
            false,
            Some("Rate limit exceeded".to_string()),
            None,
        );
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    // Set tenant context for database queries
    if let Err(e) = state.set_tenant_context(&service_context.tenant_id).await {
        tracing::error!("Failed to set tenant context: {}", e);
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    // Log successful M2M authentication
    audit.log(
        &tenant_id,
        AuditAction::Custom("m2m.auth_success"),
        ResourceType::Token,
        &service_context.service_account_id,
        None,
        None,
        Some(context),
        true,
        None,
        Some(serde_json::json!({
            "client_id": service_context.client_id,
            "auth_method": match service_context.authenticated_via {
                AuthenticationMethod::ApiKey { .. } => "api_key",
                AuthenticationMethod::ClientCredentials => "client_credentials",
            },
        })),
    );

    // Add service account context to request extensions
    request.extensions_mut().insert(service_context);

    Ok(next.run(request).await)
}

/// Optional M2M authentication middleware
///
/// Same as m2m_auth_middleware but doesn't fail if no credential is present.
/// Sets ServiceAccountContext in request extensions if valid.
pub async fn optional_m2m_auth_middleware(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    let tenant_id = extract_tenant_id(&request);

    // Try to extract credential
    if let Some(credential) = extract_credential(&request) {
        let result = if is_api_key(credential) {
            validate_api_key(&state, &tenant_id, credential).await
        } else {
            validate_m2m_token(&state, credential).await
        };

        if let Ok(service_context) = result {
            // Set tenant context (best effort)
            let _ = state.set_tenant_context(&service_context.tenant_id).await;

            // Add service account context to request extensions
            request.extensions_mut().insert(service_context);
        }
    }

    next.run(request).await
}

/// Validate an API key and return service account context
async fn validate_api_key(
    state: &AppState,
    tenant_id: &str,
    key: &str,
) -> Result<ServiceAccountContext, ApiKeyError> {
    // Validate the API key
    let validated_key = state
        .m2m_service
        .api_keys()
        .validate_key(tenant_id, key)
        .await?;

    // Get the service account details
    let service_account = state
        .m2m_service
        .get_service_account(tenant_id, &validated_key.service_account_id)
        .await
        .map_err(|e| ApiKeyError::Database(e.to_string()))?
        .ok_or(ApiKeyError::ServiceAccountNotFound)?;

    // Check if account is active
    if !service_account.is_active {
        return Err(ApiKeyError::ServiceAccountNotFound);
    }

    // Check account expiration
    if let Some(expires_at) = service_account.expires_at {
        if chrono::Utc::now() > expires_at {
            return Err(ApiKeyError::ServiceAccountNotFound);
        }
    }

    // Use key-specific scopes if set, otherwise use account scopes
    let scopes = validated_key.scopes.unwrap_or(service_account.scopes);

    Ok(ServiceAccountContext {
        service_account_id: service_account.id,
        tenant_id: service_account.tenant_id,
        client_id: service_account.client_id,
        scopes,
        permissions: service_account.permissions,
        authenticated_via: AuthenticationMethod::ApiKey {
            key_id: validated_key.key_id,
        },
    })
}

/// Validate an M2M access token and return service account context
async fn validate_m2m_token(
    state: &AppState,
    token: &str,
) -> Result<ServiceAccountContext, ClientCredentialsError> {
    let validation = state
        .m2m_service
        .client_credentials()
        .validate_token(token)
        .await?;

    Ok(ServiceAccountContext {
        service_account_id: validation.service_account_id,
        tenant_id: validation.tenant_id,
        client_id: validation.client_id,
        scopes: validation.scopes,
        permissions: validation.permissions,
        authenticated_via: AuthenticationMethod::ClientCredentials,
    })
}

/// Check rate limits for a service account
async fn check_rate_limit(
    state: &AppState,
    context: &ServiceAccountContext,
) -> Result<(), RateLimitError> {
    // Get service account rate limit config
    let service_account = state
        .m2m_service
        .get_service_account(&context.tenant_id, &context.service_account_id)
        .await
        .ok()
        .flatten();

    let (rps, burst) = service_account
        .and_then(|sa| sa.rate_limit)
        .map(|rl| (rl.requests_per_second, rl.burst))
        .unwrap_or((100, 200)); // Default limits

    // Build rate limit key
    let key = format!(
        "m2m:{}:{}",
        context.tenant_id, context.service_account_id
    );

    // Check rate limit using state rate limiter
    let allowed = state.rate_limiter.is_allowed(&key, rps, 1).await;

    if allowed {
        Ok(())
    } else {
        Err(RateLimitError::Exceeded)
    }
}

#[derive(Debug)]
enum RateLimitError {
    Exceeded,
}

/// Require specific scope middleware
///
/// Must be used after m2m_auth_middleware.
/// Checks if the service account has the required scope.
pub async fn require_scope_middleware(
    State(_state): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Get service account context from extensions
    let context = request
        .extensions()
        .get::<ServiceAccountContext>()
        .ok_or(StatusCode::UNAUTHORIZED)?;

    // Check if service account has required scopes
    // For now, just check if they have any scopes (more granular checks can be added)
    if context.scopes.is_empty() && context.permissions.is_empty() {
        return Err(StatusCode::FORBIDDEN);
    }

    Ok(next.run(request).await)
}

/// Extract service account context from request extensions
///
/// Helper function for use in handlers
pub fn extract_service_account_context(
    request: &Request,
) -> Option<ServiceAccountContext> {
    request.extensions().get::<ServiceAccountContext>().cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_credential() {
        // Create a mock request with Authorization header
        let mut request = Request::builder()
            .header(header::AUTHORIZATION, "Bearer test_token_123")
            .body(axum::body::Body::empty())
            .unwrap();

        let credential = extract_credential(&request);
        assert_eq!(credential, Some("test_token_123"));

        // Test without Bearer prefix
        let request2 = Request::builder()
            .header(header::AUTHORIZATION, "Basic dXNlcjpwYXNz")
            .body(axum::body::Body::empty())
            .unwrap();

        let credential2 = extract_credential(&request2);
        assert_eq!(credential2, None);
    }

    #[test]
    fn test_is_api_key() {
        assert!(is_api_key("vault_m2m_tenant_abc123"));
        assert!(!is_api_key("eyJhbGciOiJSUzI1NiIs")); // JWT
        assert!(!is_api_key("some_other_token"));
    }
}
