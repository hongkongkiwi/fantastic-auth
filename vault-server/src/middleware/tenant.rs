//! Tenant resolution middleware

use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};

use crate::state::{AppState, TenantContext};

/// Custom domain cache entry
#[derive(Debug, Clone)]
struct CustomDomainCache {
    tenant_id: String,
    force_https: bool,
    branding: crate::domains::custom::DomainBranding,
}

/// Extract tenant ID from request
/// 
/// Checks in order:
/// 1. X-Tenant-ID header
/// 2. X-Tenant-Slug header  
/// 3. Subdomain from Host header
fn extract_tenant_id_from_request(request: &Request) -> Option<String> {
    // Check X-Tenant-ID header
    if let Some(tenant_id) = request.headers().get("X-Tenant-ID") {
        if let Ok(id) = tenant_id.to_str() {
            return Some(id.to_string());
        }
    }

    // Check X-Tenant-Slug header
    if let Some(tenant_slug) = request.headers().get("X-Tenant-Slug") {
        if let Ok(slug) = tenant_slug.to_str() {
            return Some(slug.to_string());
        }
    }

    // Try to extract from subdomain
    if let Some(host) = request.headers().get("Host") {
        if let Ok(host_str) = host.to_str() {
            // Extract subdomain (e.g., tenant.example.com -> tenant)
            let host_str = host_str.to_lowercase();
            let parts: Vec<&str> = host_str.split('.').collect();
            if parts.len() > 2 {
                return Some(parts[0].to_string());
            }
        }
    }

    None
}

/// Tenant resolution middleware
///
/// Extracts tenant information from the request and adds it to extensions.
/// This middleware should run early in the stack.
pub async fn tenant_middleware(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Extract tenant ID
    let tenant_id = match extract_tenant_id(&request, &state).await {
        Some(id) => id,
        None => {
            // Try to get from JWT if authenticated
            if let Some(user) = request.extensions().get::<crate::state::CurrentUser>() {
                user.tenant_id.clone()
            } else {
                return Err(StatusCode::BAD_REQUEST);
            }
        }
    };

    // Validate tenant exists in database
    // TODO: Query database to validate tenant
    // For now, we'll accept any tenant ID format
    if tenant_id.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Set tenant context in database connection
    if let Err(_) = state.set_tenant_context(&tenant_id).await {
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    // Add tenant context to request extensions
    let tenant_context = TenantContext {
        tenant_id: tenant_id.clone(),
        tenant_slug: None, // TODO: Look up slug if needed
    };

    request.extensions_mut().insert(tenant_context);

    // Continue processing
    let response = next.run(request).await;

    // Clear tenant context after request (cleanup)
    let _ = clear_tenant_context(&state).await;

    Ok(response)
}

/// Extract tenant ID from request, checking custom domains
async fn extract_tenant_id(request: &Request, state: &AppState) -> Option<String> {
    // First check headers and subdomain (fast path)
    if let Some(tenant_id) = extract_tenant_id_from_request(request) {
        return Some(tenant_id);
    }

    // Try custom domain lookup from Host header
    if state.config.custom_domains.enabled {
        if let Some(host) = request.headers().get("Host") {
            if let Ok(host_str) = host.to_str() {
                let host_str = host_str.to_lowercase();
                
                // Skip if this is the base domain or an IP address
                if !is_base_or_ip(&host_str, &state.config.custom_domains.base_domain) {
                    if let Some(tenant_info) = lookup_custom_domain(state, &host_str).await {
                        return Some(tenant_info.tenant_id);
                    }
                }
            }
        }
    }

    None
}

/// Check if the host is the base domain or an IP address
fn is_base_or_ip(host: &str, base_domain: &str) -> bool {
    // Check if it's the base domain
    if host == base_domain || host == format!("www.{}", base_domain) {
        return true;
    }
    
    // Check if it's an IP address (IPv4 or IPv6)
    host.parse::<std::net::IpAddr>().is_ok()
}

/// Lookup custom domain to get tenant info
async fn lookup_custom_domain(
    state: &AppState,
    domain: &str,
) -> Option<crate::domains::custom::TenantDomainInfo> {
    use crate::domains::custom::CustomDomainRepository;
    use crate::domains::SqlxCustomDomainRepository;
    
    let repository = SqlxCustomDomainRepository::new(
        std::sync::Arc::new(state.db.pool().clone())
    );
    
    match repository.get_tenant_by_domain(domain).await {
        Ok(info) => info,
        Err(e) => {
            tracing::debug!("Custom domain lookup failed for {}: {}", domain, e);
            None
        }
    }
}

/// Clear tenant context from database connection
async fn clear_tenant_context(state: &AppState) -> anyhow::Result<()> {
    let mut conn = state.db.acquire().await?;

    sqlx::query("RESET app.current_tenant_id")
        .execute(&mut *conn)
        .await?;

    Ok(())
}

/// Get current tenant from request extensions
///
/// Helper function for handlers
pub fn get_tenant(request: &Request) -> Option<&TenantContext> {
    request.extensions().get::<TenantContext>()
}

/// Require tenant middleware
///
/// Same as tenant_middleware but fails if no tenant can be resolved.
pub async fn require_tenant_middleware(
    state: State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    tenant_middleware(state, request, next).await
}

/// Middleware to handle custom domain routing
///
/// This middleware checks if the request is coming from a custom domain
/// and sets up the appropriate context for tenant routing.
pub async fn custom_domain_middleware(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Only process if custom domains are enabled
    if !state.config.custom_domains.enabled {
        return Ok(next.run(request).await);
    }

    // Check if this is a custom domain request
    if let Some(host) = request.headers().get("Host") {
        if let Ok(host_str) = host.to_str() {
            let host_str = host_str.to_lowercase();
            
            // Skip if this is the base domain or an IP
            if !is_base_or_ip(&host_str, &state.config.custom_domains.base_domain) {
                // Check for HTTPS redirect
                if let Some(tenant_info) = lookup_custom_domain(&state, &host_str).await {
                    if tenant_info.force_https {
                        // Check if request is HTTP (you'd need to check X-Forwarded-Proto or similar)
                        // This is handled by the reverse proxy in most setups
                    }
                    
                    // Store custom domain info in request extensions
                    request.extensions_mut().insert(tenant_info);
                }
            }
        }
    }

    Ok(next.run(request).await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::HeaderValue;

    fn create_request_with_header(name: &'static str, value: &'static str) -> Request<Body> {
        let mut req = Request::new(Body::empty());
        req.headers_mut()
            .insert(name, HeaderValue::from_static(value));
        req
    }

    #[test]
    fn test_extract_tenant_id_from_header() {
        let req = create_request_with_header("X-Tenant-ID", "tenant_123");
        assert_eq!(extract_tenant_id_from_request(&req), Some("tenant_123".to_string()));
    }

    #[test]
    fn test_extract_tenant_id_from_subdomain() {
        let mut req = Request::new(Body::empty());
        req.headers_mut()
            .insert("Host", HeaderValue::from_static("mytenant.example.com"));
        assert_eq!(extract_tenant_id_from_request(&req), Some("mytenant".to_string()));
    }

    #[test]
    fn test_extract_tenant_id_no_tenant() {
        let req = Request::new(Body::empty());
        assert_eq!(extract_tenant_id_from_request(&req), None);
    }

    #[test]
    fn test_is_base_or_ip() {
        assert!(is_base_or_ip("vault.example.com", "vault.example.com"));
        assert!(is_base_or_ip("www.vault.example.com", "vault.example.com"));
        assert!(is_base_or_ip("192.168.1.1", "vault.example.com"));
        assert!(is_base_or_ip("::1", "vault.example.com"));
        assert!(!is_base_or_ip("auth.company.com", "vault.example.com"));
    }
}
