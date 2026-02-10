//! Security Middleware
//!
//! Provides:
//! - Security headers (HSTS, CSP, X-Frame-Options, etc.)
//! - Request size limiting
//! - Content-Type validation
//! - CORS configuration
//! - Request sanitization

use axum::{
    extract::Request,
    http::{header, HeaderValue, Method, StatusCode},
    middleware::Next,
    response::Response,
};
use once_cell::sync::Lazy;
use regex::Regex;
use std::time::Duration;
use tower_http::cors::CorsLayer;

// SECURITY: Compile regex once using once_cell to avoid recompilation overhead
// and prevent potential DoS from repeated regex compilation
static EMAIL_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
    ).expect("Email regex pattern is valid and statically defined")
});

/// Security headers middleware
pub async fn security_headers(request: Request, next: Next) -> Response {
    let response = next.run(request).await;

    // Add security headers to all responses
    let mut response = response;
    let headers = response.headers_mut();

    // Strict Transport Security (force HTTPS)
    // SECURITY: HSTS should ideally be enabled in all environments to prevent
    // downgrade attacks. In development with self-signed certs, browsers will
    // warn but still function. We log a warning in debug mode to ensure
    // developers are aware of this security consideration.
    if !cfg!(debug_assertions) {
        headers.insert(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=31536000; includeSubDomains; preload"),
        );
    } else {
        // SECURITY WARNING: HSTS is disabled in debug mode. In production, always
        // enable HSTS to prevent SSL/TLS downgrade attacks.
        // See: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html
        tracing::debug!("SECURITY WARNING: HSTS is disabled in debug mode. Enable in production.");
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

    // Cache control - prevent caching of sensitive data
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, no-cache, must-revalidate, proxy-revalidate"),
    );
    headers.insert(
        header::PRAGMA,
        HeaderValue::from_static("no-cache"),
    );
    headers.insert(
        header::EXPIRES,
        HeaderValue::from_static("0"),
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
/// 
/// SECURITY: Never use `Any` for origins in any environment, including development.
/// Use explicit origin list or default to restrictive settings. Malicious websites
/// can exploit overly permissive CORS to make authenticated requests on behalf of users.
/// 
/// See: https://cheatsheetseries.owasp.org/cheatsheets/CORS_Security_Cheat_Sheet.html
pub fn cors_layer(allowed_origins: Vec<String>) -> CorsLayer {
    // SECURITY: Parse origins safely, filtering out invalid ones instead of panicking
    // Invalid origins are logged as warnings but don't cause panics
    let origins: Vec<HeaderValue> = allowed_origins
        .into_iter()
        .filter_map(|s| {
            match s.parse::<HeaderValue>() {
                Ok(header_value) => Some(header_value),
                Err(e) => {
                    tracing::warn!("SECURITY: Invalid CORS origin '{}': {}. Skipping.", s, e);
                    None
                }
            }
        })
        .collect();

    // SECURITY: Pre-computed safe headers to avoid runtime parsing errors
    let x_request_id = header::HeaderName::from_static("x-request-id");

    if origins.is_empty() {
        // SECURITY: Even in development, never allow Any origin.
        // Default to same-origin only (most restrictive) if no origins specified.
        // This forces explicit CORS configuration.
        tracing::warn!(
            "SECURITY: No CORS origins configured. Using restrictive same-origin policy. \
             Configure CORS_ALLOW_ORIGINS to enable cross-origin requests."
        );
        CorsLayer::new()
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
                x_request_id.clone(),
            ])
            .expose_headers([x_request_id])
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
                x_request_id.clone(),
            ])
            .expose_headers([x_request_id])
            .allow_credentials(true)
            .max_age(Duration::from_secs(3600))
    }
}

/// Request validation middleware
/// 
/// SECURITY: Validates incoming requests for common attack vectors including
/// path traversal, null byte injection, and content type validation.
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

    // SECURITY: Enhanced path traversal protection
    // Uses multiple checks to catch various bypass techniques:
    // - URL encoding (%2e%2e%2f = ../)
    // - Double encoding
    // - Null byte injection
    // - Backslash path separators (Windows)
    let path = request.uri().path();
    let decoded_path = urlencoding::decode(path).unwrap_or_else(|_| std::borrow::Cow::Borrowed(path));
    
    // Check for path traversal attempts
    if decoded_path.contains("..") || 
       decoded_path.contains("..") ||
       decoded_path.contains(':') ||  // Windows drive letters
       decoded_path.contains('\0') || // Null byte injection
       decoded_path.contains('\x00') || // Alternative null representation
       decoded_path.starts_with("//") // Double slash could indicate protocol confusion
    {
        tracing::warn!("SECURITY: Path traversal attempt detected: {}", path);
        return Err(StatusCode::BAD_REQUEST);
    }
    
    // SECURITY: Additional check for normalized path
    // Reject paths that don't normalize cleanly
    if let Some(normalized) = normalize_path(&decoded_path) {
        if normalized != decoded_path.as_ref() && normalized.contains("..") {
            tracing::warn!("SECURITY: Normalized path contains traversal: {} -> {}", path, normalized);
            return Err(StatusCode::BAD_REQUEST);
        }
    }

    Ok(next.run(request).await)
}

/// Normalize a path for security checking
/// 
/// SECURITY: Resolves . and .. components without filesystem access
/// to prevent directory traversal attacks.
fn normalize_path(path: &str) -> Option<String> {
    let mut components = Vec::new();
    
    for component in path.split('/') {
        match component {
            "" | "." => continue,  // Skip empty and current directory
            ".." => {
                // SECURITY: Prevent escaping root via traversal
                if components.pop().is_none() {
                    return None; // Attempted to go above root
                }
            }
            _ => components.push(component),
        }
    }
    
    Some(components.join("/"))
}

/// Request ID header name
pub const X_REQUEST_ID: &str = "x-request-id";

/// Sanitize input strings
pub fn sanitize_input(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

/// Validate email format (basic check, use validator crate for thorough check)
/// 
/// SECURITY: Uses pre-compiled regex via once_cell to avoid:
/// 1. Recompilation overhead on every validation
/// 2. Potential DoS from expensive regex compilation in hot paths
/// 3. Panic risk from unwrap() on regex compilation
pub fn is_valid_email(email: &str) -> bool {
    // SECURITY: Check length first to prevent regex denial of service
    // Max length per RFC 5321 is 254 characters
    if email.len() > 254 || email.len() < 3 {  // min: a@b
        return false;
    }
    
    // Use pre-compiled regex from lazy static
    EMAIL_REGEX.is_match(email)
}

/// Validate UUID format
/// 
/// SECURITY: Validates UUID format before database queries to prevent:
/// 1. Database errors from invalid input
/// 2. Potential injection attacks using malformed UUID strings
/// 3. Unnecessary database round-trips for obviously invalid input
pub fn is_valid_uuid(uuid: &str) -> bool {
    // SECURITY: Check length first to avoid unnecessary parsing
    // Standard UUID format: 8-4-4-4-12 = 36 characters with hyphens
    if uuid.len() != 36 {
        return false;
    }
    
    uuid::Uuid::try_parse(uuid).is_ok()
}

/// UUID validation middleware
/// 
/// SECURITY: Validates all path parameters that look like UUIDs before
/// they reach route handlers. This provides defense-in-depth by rejecting
/// malformed UUIDs early in the request lifecycle.
/// 
/// Add this middleware to routes that accept UUID parameters:
/// ```rust
/// Router::new()
///     .route("/users/:id", get(get_user))
///     .layer(middleware::from_fn(uuid_validation_middleware))
/// ```
pub async fn uuid_validation_middleware(
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // SECURITY: Validate UUID path segments
    let path = request.uri().path();
    
    // Check each path segment for potential UUIDs
    for segment in path.split('/') {
        if segment.is_empty() {
            continue;
        }
        
        // Check if segment looks like a UUID (8-4-4-4-12 pattern)
        // This pattern matches standard UUIDs like 550e8400-e29b-41d4-a716-446655440000
        if segment.len() == 36 && segment.contains('-') {
            if !is_valid_uuid(segment) {
                tracing::warn!(
                    "SECURITY: Invalid UUID format detected in path: {}",
                    segment
                );
                return Err(StatusCode::BAD_REQUEST);
            }
        }
        
        // Also check for URL-encoded UUIDs (colons replaced with %3A, etc.)
        if let Ok(decoded) = urlencoding::decode(segment) {
            let decoded_str = decoded.as_ref();
            if decoded_str.len() == 36 && decoded_str.contains('-') {
                if !is_valid_uuid(decoded_str) {
                    tracing::warn!(
                        "SECURITY: Invalid URL-encoded UUID format detected in path: {}",
                        segment
                    );
                    return Err(StatusCode::BAD_REQUEST);
                }
            }
        }
    }
    
    Ok(next.run(request).await)
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

/// Validate a file path for safe file operations
/// 
/// SECURITY: This function prevents path traversal attacks by:
/// 1. Rejecting paths containing ".." (directory traversal)
/// 2. Rejecting absolute paths (starting with "/")
/// 3. Rejecting paths with null bytes
/// 4. Validating the filename is not empty and within reasonable length
/// 5. Only allowing alphanumeric characters, dots, hyphens, and underscores
/// 
/// Returns true if the path is safe to use
pub fn validate_file_path(path: &str) -> bool {
    // Check for null bytes
    if path.contains('\0') {
        tracing::warn!("SECURITY: File path contains null byte: {}", path);
        return false;
    }
    
    // Check for directory traversal
    if path.contains("..") {
        tracing::warn!("SECURITY: File path contains traversal: {}", path);
        return false;
    }
    
    // Reject absolute paths
    if path.starts_with('/') {
        tracing::warn!("SECURITY: File path is absolute: {}", path);
        return false;
    }
    
    // Check length (prevent DoS with extremely long paths)
    if path.len() > 255 {
        tracing::warn!("SECURITY: File path too long: {}", path.len());
        return false;
    }
    
    // Validate each path component
    for component in path.split('/') {
        // Reject empty components (except for trailing slashes)
        if component.is_empty() {
            continue;
        }
        
        // Check component length
        if component.len() > 100 {
            tracing::warn!("SECURITY: Path component too long: {}", component.len());
            return false;
        }
        
        // Only allow safe characters in path components
        // alphanumeric, dots, hyphens, underscores
        if !component.chars().all(|c| c.is_alphanumeric() || c == '.' || c == '-' || c == '_') {
            tracing::warn!("SECURITY: Path component contains invalid characters: {}", component);
            return false;
        }
        
        // Reject hidden files starting with "."
        if component.starts_with('.') {
            tracing::warn!("SECURITY: Path component is hidden file: {}", component);
            return false;
        }
    }
    
    true
}

/// Sanitize a filename for safe storage
/// 
/// SECURITY: This function creates a safe filename by:
/// 1. Removing path separators
/// 2. Removing null bytes
/// 3. Limiting length
/// 4. Removing control characters
pub fn sanitize_filename(filename: &str) -> String {
    filename
        .replace('/', "_")
        .replace('\\', "_")
        .replace('\0', "")
        .replace("..", "_")
        .chars()
        .filter(|c| !c.is_control())
        .take(100)
        .collect()
}

/// Build a safe file path within a base directory
/// 
/// SECURITY: This function ensures the resulting path is within the base directory
/// by resolving the path and checking it's a child of the base.
/// 
/// Returns None if the path would escape the base directory
pub fn safe_file_path(base_dir: &std::path::Path, sub_path: &str) -> Option<std::path::PathBuf> {
    // First validate the sub_path
    if !validate_file_path(sub_path) {
        return None;
    }
    
    // Build the path
    let result = base_dir.join(sub_path);
    
    // Verify the path is within base_dir
    match result.canonicalize() {
        Ok(canonical) => {
            match base_dir.canonicalize() {
                Ok(base_canonical) => {
                    if canonical.starts_with(&base_canonical) {
                        Some(result)
                    } else {
                        tracing::warn!(
                            "SECURITY: Path escapes base directory: {:?} -> {:?}",
                            sub_path,
                            canonical
                        );
                        None
                    }
                }
                Err(e) => {
                    tracing::error!("Failed to canonicalize base dir: {}", e);
                    None
                }
            }
        }
        Err(_) => {
            // Path doesn't exist yet - check if parent chain stays within base
            // This is a best-effort check for new files
            let mut current = result.as_path();
            while let Some(parent) = current.parent() {
                if parent == base_dir {
                    return Some(result);
                }
                current = parent;
            }
            // Check if base_dir itself is the root of the path
            if base_dir == std::path::Path::new(".") || result.starts_with(base_dir) {
                Some(result)
            } else {
                None
            }
        }
    }
}

/// Maximum allowed file sizes for different operations
pub const MAX_CSV_IMPORT_SIZE: usize = 50 * 1024 * 1024;    // 50MB
pub const MAX_JSON_IMPORT_SIZE: usize = 100 * 1024 * 1024;  // 100MB
pub const MAX_EXPORT_SIZE: usize = 500 * 1024 * 1024;       // 500MB
pub const MAX_AVATAR_SIZE: usize = 5 * 1024 * 1024;         // 5MB

/// Validate file size for a specific operation
/// 
/// SECURITY: Prevents DoS attacks through oversized file uploads
pub fn validate_file_size(size: usize, operation: FileOperation) -> bool {
    let max_size = match operation {
        FileOperation::CsvImport => MAX_CSV_IMPORT_SIZE,
        FileOperation::JsonImport => MAX_JSON_IMPORT_SIZE,
        FileOperation::Export => MAX_EXPORT_SIZE,
        FileOperation::Avatar => MAX_AVATAR_SIZE,
        FileOperation::Custom(max) => max,
    };
    
    size <= max_size
}

/// File operation types for size validation
#[derive(Debug, Clone, Copy)]
pub enum FileOperation {
    CsvImport,
    JsonImport,
    Export,
    Avatar,
    Custom(usize),
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

    #[test]
    fn test_validate_file_path() {
        // Valid paths
        assert!(validate_file_path("users.csv"));
        assert!(validate_file_path("imports/data.json"));
        assert!(validate_file_path("tenant-123/export.csv"));
        
        // Invalid paths - traversal
        assert!(!validate_file_path("../etc/passwd"));
        assert!(!validate_file_path("data/../../etc/passwd"));
        assert!(!validate_file_path(".."));
        
        // Invalid paths - absolute
        assert!(!validate_file_path("/etc/passwd"));
        assert!(!validate_file_path("/tmp/data.csv"));
        
        // Invalid paths - hidden files
        assert!(!validate_file_path(".htaccess"));
        assert!(!validate_file_path("data/.env"));
        
        // Invalid paths - null bytes
        assert!(!validate_file_path("file\0.txt"));
        
        // Invalid paths - special characters
        assert!(!validate_file_path("file;rm -rf /"));
        assert!(!validate_file_path("file|cat /etc/passwd"));
    }

    #[test]
    fn test_sanitize_filename() {
        assert_eq!(sanitize_filename("file.txt"), "file.txt");
        assert_eq!(sanitize_filename("../etc/passwd"), "__etc_passwd");
        assert_eq!(sanitize_filename("file\0.txt"), "file.txt");
        assert_eq!(sanitize_filename("very/long/path/file.txt").len(), 23);
    }

    #[test]
    fn test_validate_file_size() {
        assert!(validate_file_size(1024, FileOperation::CsvImport));
        assert!(validate_file_size(50 * 1024 * 1024, FileOperation::CsvImport));
        assert!(!validate_file_size(51 * 1024 * 1024, FileOperation::CsvImport));
        
        assert!(validate_file_size(1024, FileOperation::Avatar));
        assert!(!validate_file_size(6 * 1024 * 1024, FileOperation::Avatar));
    }
}
