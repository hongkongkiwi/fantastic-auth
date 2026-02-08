//! Security Middleware
//!
//! Provides:
//! - Security headers (HSTS, CSP, X-Frame-Options, etc.)
//! - Request size limiting
//! - Content-Type validation
//! - CORS configuration
//! - Request sanitization

use axum::{
    body::Body,
    extract::Request,
    http::{header, HeaderValue, Method, StatusCode, Uri},
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::time::Duration;
use tower_http::cors::{Any, CorsLayer};

/// Security headers middleware
pub async fn security_headers(request: Request, next: Next) -> Response {
    let response = next.run(request).await;

    // Add security headers to all responses
    let mut response = response;
    let headers = response.headers_mut();

    // Strict Transport Security (force HTTPS)
    // Only in production
    if !cfg!(debug_assertions) {
        headers.insert(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=31536000; includeSubDomains; preload"),
        );
    }

    // Content Security Policy
    headers.insert(
        "Content-Security-Policy",
        HeaderValue::from_static(
            "default-src 'self'; \
             script-src 'self'; \
             style-src 'self' 'unsafe-inline'; \
             img-src 'self' data: https:; \
             font-src 'self'; \
             connect-src 'self'; \
             frame-ancestors 'none'; \
             base-uri 'self'; \
             form-action 'self';",
        ),
    );

    // Prevent clickjacking
    headers.insert("X-Frame-Options", HeaderValue::from_static("DENY"));

    // Prevent MIME type sniffing
    headers.insert(
        "X-Content-Type-Options",
        HeaderValue::from_static("nosniff"),
    );

    // XSS Protection
    headers.insert(
        "X-XSS-Protection",
        HeaderValue::from_static("1; mode=block"),
    );

    // Referrer Policy
    headers.insert(
        "Referrer-Policy",
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );

    // Permissions Policy
    headers.insert(
        "Permissions-Policy",
        HeaderValue::from_static(
            "accelerometer=(), \
             camera=(), \
             geolocation=(), \
             gyroscope=(), \
             magnetometer=(), \
             microphone=(), \
             payment=(), \
             usb=()",
        ),
    );

    // Remove server identification
    headers.remove(header::SERVER);

    response
}

/// CORS layer configuration
pub fn cors_layer(allowed_origins: Vec<String>) -> CorsLayer {
    let origins: Vec<HeaderValue> = allowed_origins
        .into_iter()
        .map(|s| s.parse().unwrap())
        .collect();

    if origins.is_empty() {
        // Allow all origins in development
        CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers(Any)
            .expose_headers(["x-request-id".parse().unwrap()])
            .max_age(Duration::from_secs(3600))
    } else {
        CorsLayer::new()
            .allow_origin(origins)
            .allow_methods([
                Method::GET,
                Method::POST,
                Method::PUT,
                Method::PATCH,
                Method::DELETE,
                Method::OPTIONS,
            ])
            .allow_headers([
                header::AUTHORIZATION,
                header::CONTENT_TYPE,
                header::ACCEPT,
                "x-request-id".parse().unwrap(),
            ])
            .expose_headers(["x-request-id".parse().unwrap()])
            .allow_credentials(true)
            .max_age(Duration::from_secs(3600))
    }
}

/// Request validation middleware
pub async fn validate_request(request: Request, next: Next) -> Result<Response, StatusCode> {
    // Validate Content-Type for POST/PUT/PATCH requests
    if matches!(
        request.method(),
        &Method::POST | &Method::PUT | &Method::PATCH
    ) {
        if let Some(content_type) = request.headers().get(header::CONTENT_TYPE) {
            let content_type = content_type.to_str().unwrap_or("");

            // Only allow JSON and form data
            if !content_type.starts_with("application/json")
                && !content_type.starts_with("application/x-www-form-urlencoded")
                && !content_type.starts_with("multipart/form-data")
            {
                return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE);
            }
        }
    }

    // Validate path characters (prevent path traversal)
    let path = request.uri().path();
    if path.contains("..") || path.contains('\0') {
        return Err(StatusCode::BAD_REQUEST);
    }

    Ok(next.run(request).await)
}

/// Request ID header name
pub const X_REQUEST_ID: &str = "x-request-id";

/// Sanitize input strings
pub fn sanitize_input(input: &str) -> String {
    input
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
        .replace('&', "&amp;")
}

/// Validate email format (basic check, use validator crate for thorough check)
pub fn is_valid_email(email: &str) -> bool {
    // RFC 5322 compliant regex (simplified)
    let email_regex = regex::Regex::new(
        r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
    ).unwrap();

    email_regex.is_match(email) && email.len() <= 254
}

/// Validate UUID format
pub fn is_valid_uuid(uuid: &str) -> bool {
    uuid::Uuid::try_parse(uuid).is_ok()
}

/// Rate limit key generator
pub fn rate_limit_key(client_ip: &str, endpoint: &str) -> String {
    format!("rate_limit:{}:{}", client_ip, endpoint)
}

/// Security event logging
pub fn log_security_event(event: SecurityEvent) {
    use tracing::warn;

    match event {
        SecurityEvent::InvalidToken { ip, reason } => {
            warn!(
                event = "invalid_token",
                ip = %ip,
                reason = %reason,
                "Invalid authentication token received"
            );
        }
        SecurityEvent::RateLimitExceeded { ip, endpoint } => {
            warn!(
                event = "rate_limit_exceeded",
                ip = %ip,
                endpoint = %endpoint,
                "Rate limit exceeded"
            );
        }
        SecurityEvent::SuspiciousRequest { ip, path, reason } => {
            warn!(
                event = "suspicious_request",
                ip = %ip,
                path = %path,
                reason = %reason,
                "Suspicious request detected"
            );
        }
        SecurityEvent::SqlInjectionAttempt { ip, query } => {
            warn!(
                event = "sql_injection_attempt",
                ip = %ip,
                query = %query,
                "Potential SQL injection attempt"
            );
        }
        SecurityEvent::BruteForceAttempt { ip, email } => {
            warn!(
                event = "brute_force_attempt",
                ip = %ip,
                email = %email,
                "Potential brute force attack"
            );
        }
    }
}

/// Security events for logging
#[derive(Debug)]
pub enum SecurityEvent {
    InvalidToken {
        ip: String,
        reason: String,
    },
    RateLimitExceeded {
        ip: String,
        endpoint: String,
    },
    SuspiciousRequest {
        ip: String,
        path: String,
        reason: String,
    },
    SqlInjectionAttempt {
        ip: String,
        query: String,
    },
    BruteForceAttempt {
        ip: String,
        email: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_input() {
        assert_eq!(
            sanitize_input("<script>alert('xss')</script>"),
            "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;"
        );
    }

    #[test]
    fn test_is_valid_email() {
        assert!(is_valid_email("user@example.com"));
        assert!(is_valid_email("user.name+tag@example.co.uk"));
        assert!(!is_valid_email("invalid"));
        assert!(!is_valid_email("@example.com"));
        assert!(!is_valid_email("user@"));
    }

    #[test]
    fn test_is_valid_uuid() {
        assert!(is_valid_uuid("550e8400-e29b-41d4-a716-446655440000"));
        assert!(!is_valid_uuid("invalid-uuid"));
        assert!(!is_valid_uuid(""));
    }
}
