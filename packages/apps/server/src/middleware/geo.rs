//! Geographic restriction middleware
//!
//! Provides middleware for enforcing geographic access restrictions.
//! Extracts client IP from various headers, performs GeoIP lookups,
//! and blocks requests from restricted countries or VPN/proxy sources.

use axum::{
    extract::{ConnectInfo, Request, State},
    http::{header::HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::net::{IpAddr, SocketAddr};

use crate::audit::{AuditAction, AuditLogger, RequestContext, ResourceType};
use crate::security::geo::GeoAccessResult;
use crate::state::{AppState, CurrentUser, TenantContext};

/// Extension key for storing geo lookup result in request extensions
#[derive(Debug, Clone)]
pub struct GeoInfo {
    /// Country code (ISO 3166-1 alpha-2)
    pub country_code: Option<String>,
    /// Whether the IP is from a VPN
    pub is_vpn: bool,
    /// Whether the IP is from an anonymous proxy
    pub is_anonymous_proxy: bool,
    /// Whether the IP is from a hosting provider
    pub is_hosting_provider: bool,
    /// Client IP address
    pub ip_address: String,
}

impl GeoInfo {
    /// Check if the connection is from any type of proxy/VPN
    pub fn is_proxy_or_vpn(&self) -> bool {
        self.is_vpn || self.is_anonymous_proxy || self.is_hosting_provider
    }
}

/// Extract client IP address from request headers and connection info
///
/// Priority order:
/// 1. CF-Connecting-IP (Cloudflare)
/// 2. X-Forwarded-For (first IP in chain)
/// 3. X-Real-IP
/// 4. Connection socket address
pub fn extract_client_ip(headers: &HeaderMap, addr: &SocketAddr) -> IpAddr {
    // Check Cloudflare header first (most trusted)
    if let Some(ip) = headers
        .get("cf-connecting-ip")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.trim().parse::<IpAddr>().ok())
    {
        return ip;
    }

    // Check X-Forwarded-For (common with proxies)
    if let Some(ip) = headers
        .get("x-forwarded-for")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| {
            // Take the first IP in the chain (client IP)
            s.split(',')
                .next()
                .map(|ip| ip.trim().parse::<IpAddr>().ok())
        })
        .flatten()
    {
        return ip;
    }

    // Check X-Real-IP
    if let Some(ip) = headers
        .get("x-real-ip")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.trim().parse::<IpAddr>().ok())
    {
        return ip;
    }

    // Fallback to connection address
    addr.ip()
}

/// Geographic restriction middleware
///
/// This middleware checks if the client's IP address is allowed based on
/// the configured geographic restrictions. It also adds GeoInfo to the
/// request extensions for downstream use.
///
/// # Headers
///
/// - `X-Country-Code` - Added to response with the detected country code
/// - `X-Geo-Restricted` - Added to response if access was blocked
///
/// # Errors
///
/// Returns 403 Forbidden if the IP is blocked by geo restrictions
pub async fn geo_restriction_middleware(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    mut request: Request,
    next: Next,
) -> Result<Response, GeoRestrictionError> {
    // Skip if geo restrictions are disabled
    if !state.config.security.geo_restriction.enabled {
        return Ok(next.run(request).await);
    }

    // Extract client IP
    let client_ip = extract_client_ip(request.headers(), &addr);

    // Get tenant context if available
    let tenant_id = request
        .extensions()
        .get::<CurrentUser>()
        .map(|u| u.tenant_id.clone())
        .or_else(|| {
            request
                .extensions()
                .get::<TenantContext>()
                .map(|t| t.tenant_id.clone())
        });

    // Check geo restrictions using the global config
    // In a real implementation, you might want to fetch tenant-specific config from DB
    let geo_config = &state.config.security.geo_restriction;

    // If geo restrictions are not enabled globally, skip
    if !geo_config.enabled {
        return Ok(next.run(request).await);
    }

    // Get or create geo restriction service
    // Note: In production, this should be stored in AppState
    let result = check_geo_restriction(&state, client_ip, tenant_id.as_deref()).await;

    match result {
        Ok(access_result) => {
            if access_result.allowed {
                // Add GeoInfo to request extensions for downstream use
                let geo_info = GeoInfo {
                    country_code: access_result.country_code.clone(),
                    is_vpn: access_result
                        .geo_info
                        .as_ref()
                        .map(|g| g.is_vpn)
                        .unwrap_or(false),
                    is_anonymous_proxy: access_result
                        .geo_info
                        .as_ref()
                        .map(|g| g.is_anonymous_proxy)
                        .unwrap_or(false),
                    is_hosting_provider: access_result
                        .geo_info
                        .as_ref()
                        .map(|g| g.is_hosting_provider)
                        .unwrap_or(false),
                    ip_address: client_ip.to_string(),
                };
                request.extensions_mut().insert(geo_info);

                // Run the next middleware/handler
                let mut response = next.run(request).await;

                // Add country header to response
                if let Some(country) = access_result.country_code {
                    if let Ok(header_value) = country.parse() {
                        response
                            .headers_mut()
                            .insert("X-Country-Code", header_value);
                    }
                }

                Ok(response)
            } else {
                // Log blocked access
                let audit = AuditLogger::new(state.db.clone());
                let request_context =
                    RequestContext::from_request(request.headers(), Some(&ConnectInfo(addr)));

                audit.log(
                    tenant_id.as_deref().unwrap_or("system"),
                    AuditAction::Custom("geo.access_denied"),
                    ResourceType::User,
                    &client_ip.to_string(),
                    None,
                    None,
                    Some(request_context),
                    false,
                    access_result.reason.clone(),
                    Some(serde_json::json!({
                        "ip": client_ip.to_string(),
                        "country": access_result.country_code,
                    })),
                );

                Err(GeoRestrictionError {
                    reason: access_result.reason.unwrap_or_else(|| {
                        "Access denied by geographic restriction policy".to_string()
                    }),
                    country_code: access_result.country_code,
                })
            }
        }
        Err(e) => {
            // Log error but allow request (fail open to avoid blocking legitimate traffic)
            tracing::error!(error = %e, ip = %client_ip, "GeoIP lookup failed");

            // Add error info to request extensions
            request.extensions_mut().insert(GeoInfo {
                country_code: None,
                is_vpn: false,
                is_anonymous_proxy: false,
                is_hosting_provider: false,
                ip_address: client_ip.to_string(),
            });

            Ok(next.run(request).await)
        }
    }
}

/// Check geo restrictions for an IP address
async fn check_geo_restriction(
    state: &AppState,
    ip: IpAddr,
    tenant_id: Option<&str>,
) -> Result<GeoAccessResult, GeoRestrictionError> {
    // In a real implementation, you might want to:
    // 1. Check tenant-specific geo restrictions from database
    // 2. Use a cached geo restriction service from AppState

    // For now, we'll use a simplified check based on global config
    let config = &state.config.security.geo_restriction;

    if !config.enabled {
        return Ok(GeoAccessResult::allowed());
    }

    // Skip private IPs
    if is_private_ip(ip) {
        return Ok(GeoAccessResult::allowed());
    }

    // Get geo info from cache or external service
    let geo_info = match get_geo_info(state, ip).await {
        Ok(info) => info,
        Err(e) => {
            tracing::warn!(error = %e, ip = %ip, "Failed to get geo info");
            return Ok(GeoAccessResult::allowed());
        }
    };

    // Check VPN/proxy restrictions
    if geo_info.is_vpn && !config.allow_vpn {
        return Ok(GeoAccessResult::blocked(
            "VPN connections are not allowed",
            geo_info.country_code.clone(),
        ));
    }

    if geo_info.is_anonymous_proxy && config.block_anonymous_proxies {
        return Ok(GeoAccessResult::blocked(
            "Anonymous proxies are not allowed",
            geo_info.country_code.clone(),
        ));
    }

    // Check country restrictions
    let country_code = geo_info.country_code.clone().unwrap_or_default();
    let country_list: std::collections::HashSet<String> =
        config.country_list.iter().cloned().collect();

    let allowed = match config.policy {
        crate::config::GeoRestrictionPolicy::AllowList => {
            country_list.is_empty() || country_list.contains(&country_code)
        }
        crate::config::GeoRestrictionPolicy::BlockList => {
            !country_list.contains(&country_code)
        }
    };

    if allowed {
        Ok(GeoAccessResult::allowed_with_geo(geo_info))
    } else {
        Ok(GeoAccessResult::blocked(
            &format!("Access from country '{}' is not permitted", country_code),
            Some(country_code),
        ))
    }
}

/// Get geo info from cache or external service
async fn get_geo_info(
    state: &AppState,
    ip: IpAddr,
) -> Result<crate::security::geo::GeoIpLookupResult, Box<dyn std::error::Error + Send + Sync>> {
    use crate::security::geo::GeoIpLookupResult;

    // Try to get from Redis cache
    if let Some(ref redis) = state.redis {
        let cache_key = format!("geoip:lookup:{}", ip);
        let mut conn = redis.clone();

        let cached: Option<String> = redis::cmd("GET")
            .arg(&cache_key)
            .query_async(&mut conn)
            .await?;

        if let Some(json) = cached {
            if let Ok(result) = serde_json::from_str::<GeoIpLookupResult>(&json) {
                return Ok(result);
            }
        }
    }

    // In a real implementation, you would perform the MaxMind lookup here
    // For now, return unknown
    let result = GeoIpLookupResult::unknown();

    // Cache the result
    if let Some(ref redis) = state.redis {
        let cache_key = format!("geoip:lookup:{}", ip);
        let mut conn = redis.clone();

        if let Ok(json) = serde_json::to_string(&result) {
            let ttl = state.config.security.geo_restriction.cache_ttl_seconds;
            let _: Result<(), _> = redis::cmd("SETEX")
                .arg(&cache_key)
                .arg(ttl)
                .arg(json)
                .query_async(&mut conn)
                .await;
        }
    }

    Ok(result)
}

/// Check if an IP address is private
fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(addr) => {
            addr.is_private()
                || addr.is_loopback()
                || addr.is_link_local()
                || addr.is_multicast()
                || addr.is_broadcast()
                || addr.is_documentation()
        }
        IpAddr::V6(addr) => addr.is_loopback() || addr.is_multicast() || addr.is_unspecified(),
    }
}

/// Geo restriction error response
#[derive(Debug)]
pub struct GeoRestrictionError {
    reason: String,
    country_code: Option<String>,
}

impl std::fmt::Display for GeoRestrictionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.country_code {
            Some(code) => write!(f, "{} (country: {})", self.reason, code),
            None => write!(f, "{}", self.reason),
        }
    }
}

impl IntoResponse for GeoRestrictionError {
    fn into_response(self) -> Response {
        let body = serde_json::json!({
            "error": {
                "code": "GEO_RESTRICTED",
                "message": self.reason,
                "country_code": self.country_code,
            }
        });

        let mut response = (StatusCode::FORBIDDEN, axum::Json(body)).into_response();

        // Add headers to indicate geo restriction
        response
            .headers_mut()
            .insert("X-Geo-Restricted", "true".parse().unwrap());

        if let Some(country) = self.country_code {
            if let Ok(header_value) = country.parse() {
                response
                    .headers_mut()
                    .insert("X-Country-Code", header_value);
            }
        }

        response
    }
}

/// Geo restriction middleware that only logs (for monitoring)
///
/// This middleware performs geo lookups and logs the results without blocking.
/// Useful for monitoring geographic access patterns before enforcing restrictions.
pub async fn geo_logging_middleware(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    mut request: Request,
    next: Next,
) -> Response {
    let client_ip = extract_client_ip(request.headers(), &addr);

    // Perform geo lookup if we have a geo service configured
    if let Ok(geo_info) = get_geo_info(&state, client_ip).await {
        let geo_ext = GeoInfo {
            country_code: geo_info.country_code.clone(),
            is_vpn: geo_info.is_vpn,
            is_anonymous_proxy: geo_info.is_anonymous_proxy,
            is_hosting_provider: geo_info.is_hosting_provider,
            ip_address: client_ip.to_string(),
        };

        request.extensions_mut().insert(geo_ext);

        // Log for monitoring
        tracing::info!(
            ip = %client_ip,
            country = ?geo_info.country_code,
            is_vpn = geo_info.is_vpn,
            path = %request.uri().path(),
            "Geo lookup result"
        );
    }

    next.run(request).await
}

/// Helper trait to extract GeoInfo from request extensions
pub trait GeoInfoExt {
    /// Get geo info from request
    fn geo_info(&self) -> Option<&GeoInfo>;

    /// Get country code from request
    fn country_code(&self) -> Option<&str>;

    /// Check if request is from a VPN/proxy
    fn is_from_proxy(&self) -> bool;
}

impl GeoInfoExt for Request {
    fn geo_info(&self) -> Option<&GeoInfo> {
        self.extensions().get::<GeoInfo>()
    }

    fn country_code(&self) -> Option<&str> {
        self.extensions()
            .get::<GeoInfo>()
            .and_then(|g| g.country_code.as_deref())
    }

    fn is_from_proxy(&self) -> bool {
        self.extensions()
            .get::<GeoInfo>()
            .map(|g| g.is_proxy_or_vpn())
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_client_ip_from_cloudflare() {
        let mut headers = HeaderMap::new();
        headers.insert("cf-connecting-ip", "203.0.113.1".parse().unwrap());

        let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
        let ip = extract_client_ip(&headers, &addr);

        assert_eq!(ip.to_string(), "203.0.113.1");
    }

    #[test]
    fn test_extract_client_ip_from_x_forwarded_for() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            "203.0.113.1, 198.51.100.1".parse().unwrap(),
        );

        let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
        let ip = extract_client_ip(&headers, &addr);

        assert_eq!(ip.to_string(), "203.0.113.1");
    }

    #[test]
    fn test_extract_client_ip_from_x_real_ip() {
        let mut headers = HeaderMap::new();
        headers.insert("x-real-ip", "203.0.113.2".parse().unwrap());

        let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
        let ip = extract_client_ip(&headers, &addr);

        assert_eq!(ip.to_string(), "203.0.113.2");
    }

    #[test]
    fn test_extract_client_ip_fallback() {
        let headers = HeaderMap::new();
        let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
        let ip = extract_client_ip(&headers, &addr);

        assert_eq!(ip.to_string(), "127.0.0.1");
    }

    #[test]
    fn test_geo_info_proxy_detection() {
        let geo_info = GeoInfo {
            country_code: Some("US".to_string()),
            is_vpn: true,
            is_anonymous_proxy: false,
            is_hosting_provider: false,
            ip_address: "203.0.113.1".to_string(),
        };
        assert!(geo_info.is_proxy_or_vpn());

        let geo_info2 = GeoInfo {
            country_code: Some("US".to_string()),
            is_vpn: false,
            is_anonymous_proxy: false,
            is_hosting_provider: false,
            ip_address: "203.0.113.1".to_string(),
        };
        assert!(!geo_info2.is_proxy_or_vpn());
    }
}
