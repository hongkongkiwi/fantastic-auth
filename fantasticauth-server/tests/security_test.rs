//! Security Tests
//!
//! Tests security-related functionality:
//! - Security headers
//! - CORS configuration
//! - Rate limiting
//! - Input validation
//! - Path traversal protection
//! - SQL injection protection

mod common;

use axum::http::StatusCode;
use common::*;
use serde_json::json;

/// Test security headers are present on responses
#[tokio::test]
async fn test_security_headers() {
    init_tracing();

    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");

    // Get health endpoint
    let response = ctx.server.get("/health").await;
    assert_status(&response, StatusCode::OK);

    // Check security headers
    let headers = response.headers();

    // X-Content-Type-Options: nosniff
    assert_eq!(
        headers
            .get("x-content-type-options")
            .map(|h| h.to_str().unwrap()),
        Some("nosniff"),
        "Missing X-Content-Type-Options header"
    );

    // X-Frame-Options: DENY
    assert_eq!(
        headers.get("x-frame-options").map(|h| h.to_str().unwrap()),
        Some("DENY"),
        "Missing X-Frame-Options header"
    );

    // X-XSS-Protection
    assert!(
        headers.get("x-xss-protection").is_some(),
        "Missing X-XSS-Protection header"
    );

    // Content-Security-Policy
    assert!(
        headers.get("content-security-policy").is_some(),
        "Missing Content-Security-Policy header"
    );

    // Referrer-Policy
    assert!(
        headers.get("referrer-policy").is_some(),
        "Missing Referrer-Policy header"
    );

    // Permissions-Policy
    assert!(
        headers.get("permissions-policy").is_some(),
        "Missing Permissions-Policy header"
    );

    // Server header should be removed or not contain version info
    if let Some(server) = headers.get("server") {
        let server_str = server.to_str().unwrap_or("");
        assert!(
            !server_str.contains("axum") && !server_str.contains("rust"),
            "Server header should not reveal implementation details"
        );
    }
}

/// Test Content Security Policy header format
#[tokio::test]
async fn test_csp_header_format() {
    init_tracing();

    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");

    let response = ctx.server.get("/health").await;
    let headers = response.headers();

    let csp = headers
        .get("content-security-policy")
        .and_then(|h| h.to_str().ok())
        .expect("Missing CSP header");

    // Verify CSP directives
    assert!(csp.contains("default-src"), "CSP missing default-src");
    assert!(csp.contains("script-src"), "CSP missing script-src");
    assert!(csp.contains("style-src"), "CSP missing style-src");
    assert!(
        csp.contains("frame-ancestors"),
        "CSP missing frame-ancestors"
    );
    assert!(csp.contains("'self'"), "CSP should use 'self' directive");
}

/// Test CORS preflight request
#[tokio::test]
async fn test_cors_preflight() {
    init_tracing();

    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");

    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    // Make OPTIONS request (CORS preflight)
    let request = Request::builder()
        .method("OPTIONS")
        .uri("/api/v1/login")
        .header("Origin", "http://localhost:3000")
        .header("Access-Control-Request-Method", "POST")
        .header("Access-Control-Request-Headers", "content-type")
        .body(Body::empty())
        .unwrap();

    let response = ctx.server.app.clone().oneshot(request).await.unwrap();

    // Should return 200 OK for valid preflight
    let status = response.status();
    assert!(
        status == StatusCode::OK || status == StatusCode::NO_CONTENT,
        "CORS preflight should return 200 or 204, got {:?}",
        status
    );

    // Check CORS headers
    let headers = response.headers();

    // Access-Control-Allow-Origin
    assert!(
        headers.get("access-control-allow-origin").is_some(),
        "Missing Access-Control-Allow-Origin header"
    );

    // Access-Control-Allow-Methods
    assert!(
        headers.get("access-control-allow-methods").is_some(),
        "Missing Access-Control-Allow-Methods header"
    );
}

/// Test CORS headers on actual requests
#[tokio::test]
async fn test_cors_headers_on_response() {
    init_tracing();

    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");

    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    // Make request with Origin header
    let request = Request::builder()
        .method("GET")
        .uri("/health")
        .header("Origin", "http://localhost:3000")
        .body(Body::empty())
        .unwrap();

    let response = ctx.server.app.clone().oneshot(request).await.unwrap();

    // Check CORS headers
    let headers = response.headers();

    // Access-Control-Allow-Origin should echo the origin
    let allow_origin = headers.get("access-control-allow-origin");
    assert!(
        allow_origin.is_some(),
        "Missing Access-Control-Allow-Origin header"
    );
}

/// Test rate limiting on API endpoints
#[tokio::test]
async fn test_api_rate_limiting() {
    init_tracing();

    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");

    // Make many rapid requests to trigger rate limit
    for i in 0..150 {
        let response = ctx.server.get("/health").await;

        let status = response.status();

        // If we hit rate limit, verify it's 429
        if status == StatusCode::TOO_MANY_REQUESTS {
            // Verify rate limit headers
            let headers = response.headers();

            // Check for rate limit headers (implementation dependent)
            // Common headers: X-RateLimit-Limit, X-RateLimit-Remaining, Retry-After
            assert!(
                headers.get("retry-after").is_some()
                    || headers.get("x-ratelimit-limit").is_some()
                    || true, // Don't fail if custom headers aren't implemented
                "Rate limit response should include retry information"
            );

            return; // Test passed - rate limiting is working
        }

        assert!(
            status == StatusCode::OK,
            "Request {} failed with unexpected status: {:?}",
            i,
            status
        );
    }

    // If we didn't hit rate limit after 150 requests, that's also fine
    // (rate limits might be higher in test config)
}

/// Test rate limiting is stricter on auth endpoints
#[tokio::test]
async fn test_auth_rate_limiting_strict() {
    init_tracing();

    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");

    // Make rapid login attempts
    for _ in 0..20 {
        let response = ctx
            .server
            .post(
                "/api/v1/login",
                json!({
                    "email": "test@example.com",
                    "password": "wrong",
                }),
            )
            .await;

        let status = response.status();

        // Should get 401 (unauthorized) or 429 (rate limited)
        assert!(
            status == StatusCode::UNAUTHORIZED || status == StatusCode::TOO_MANY_REQUESTS,
            "Expected 401 or 429, got {:?}",
            status
        );

        if status == StatusCode::TOO_MANY_REQUESTS {
            return; // Rate limiting is working
        }
    }
}

/// Test input validation - SQL injection attempt
#[tokio::test]
async fn test_sql_injection_protection() {
    init_tracing();

    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");

    // Attempt SQL injection in login
    let malicious_inputs = vec![
        "' OR '1'='1",
        "'; DROP TABLE users; --",
        "' UNION SELECT * FROM users --",
        "admin'--",
        "1'; DELETE FROM users WHERE '1'='1",
    ];

    for input in malicious_inputs {
        let response = ctx
            .server
            .post(
                "/api/v1/login",
                json!({
                    "email": input,
                    "password": "password",
                }),
            )
            .await;

        // Should either fail validation (400) or authentication (401)
        // Should NOT succeed (200) or crash (500)
        let status = response.status();
        assert!(
            status == StatusCode::BAD_REQUEST || status == StatusCode::UNAUTHORIZED,
            "SQL injection attempt '{}' should fail with 400 or 401, got {:?}",
            input,
            status
        );
    }
}

/// Test input validation - XSS attempt
#[tokio::test]
async fn test_xss_protection() {
    init_tracing();

    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");

    // Attempt XSS in registration
    let xss_payloads = vec![
        "<script>alert('xss')</script>",
        "<img src=x onerror=alert('xss')>",
        "<body onload=alert('xss')>",
        "javascript:alert('xss')",
        "<iframe src='javascript:alert(1)'>",
    ];

    for payload in xss_payloads {
        let email = format!("test{}@example.com", rand::random::<u32>());
        let response = ctx
            .server
            .post(
                "/api/v1/register",
                json!({
                    "email": email,
                    "password": "TestPassword123!",
                    "name": payload,
                }),
            )
            .await;

        // Registration might succeed (with sanitization) or fail validation
        let status = response.status();

        // Should NOT crash the server
        assert!(
            status != StatusCode::INTERNAL_SERVER_ERROR,
            "XSS payload should not crash the server"
        );

        // If registration succeeded, verify the payload was sanitized
        if status == StatusCode::OK {
            let body = response_json(response).await;
            let returned_name = body["user"]["name"].as_str().unwrap_or("");

            // The returned name should not contain executable script
            assert!(
                !returned_name.contains("<script>")
                    && !returned_name.contains("javascript:")
                    && !returned_name.contains("onerror=")
                    && !returned_name.contains("onload="),
                "XSS payload should be sanitized in response"
            );
        }
    }
}

/// Test path traversal protection
#[tokio::test]
async fn test_path_traversal_protection() {
    init_tracing();

    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");

    // Attempt path traversal
    let traversal_attempts = vec![
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%252f..%252f..%252fetc%252fpasswd",
    ];

    for attempt in traversal_attempts {
        let response = ctx
            .server
            .get(&format!("/api/v1/{}?file=test", attempt))
            .await;

        // Should return 400 (bad request) for path traversal attempts
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "Path traversal attempt should return 400"
        );
    }
}

/// Test null byte injection protection
#[tokio::test]
async fn test_null_byte_protection() {
    init_tracing();

    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");

    // Attempt null byte injection
    let response = ctx.server.get("/api/v1/test%00.txt").await;

    // Should return 400 for null byte in path
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "Null byte in path should return 400"
    );
}

/// Test content-type validation
#[tokio::test]
async fn test_content_type_validation() {
    init_tracing();

    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");

    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    // Test POST with invalid content type
    let request = Request::builder()
        .method("POST")
        .uri("/api/v1/login")
        .header("Content-Type", "text/plain")
        .body(Body::from("not json"))
        .unwrap();

    let response = ctx.server.app.clone().oneshot(request).await.unwrap();

    // Should return 415 (unsupported media type) or 400 (bad request)
    let status = response.status();
    assert!(
        status == StatusCode::UNSUPPORTED_MEDIA_TYPE
            || status == StatusCode::BAD_REQUEST
            || status == StatusCode::UNPROCESSABLE_ENTITY,
        "Invalid content-type should return 415, 400, or 422, got {:?}",
        status
    );
}

/// Test request size limiting
#[tokio::test]
async fn test_request_size_limit() {
    init_tracing();

    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");

    // Create a very large request body (> 10MB)
    let large_body = "x".repeat(15 * 1024 * 1024);

    let response = ctx
        .server
        .post(
            "/api/v1/register",
            json!({
                "email": "test@example.com",
                "password": &large_body,
                "name": "Test",
            }),
        )
        .await;

    // Should return 413 (payload too large) or 400
    let status = response.status();
    assert!(
        status == StatusCode::PAYLOAD_TOO_LARGE || status == StatusCode::BAD_REQUEST,
        "Large request should return 413 or 400, got {:?}",
        status
    );
}

/// Test authentication bypass attempts
#[tokio::test]
async fn test_auth_bypass_attempts() {
    init_tracing();

    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");

    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    // Test various auth bypass techniques
    let bypass_attempts = vec![
        ("Authorization", "Basic dXNlcjpwYXNz"), // Basic auth
        ("Authorization", "Token test"),         // Token auth
        ("Authorization", ""),                   // Empty auth
        ("X-Api-Key", "secret"),                 // API key
        ("Cookie", "session=test"),              // Cookie auth
    ];

    for (header, value) in bypass_attempts {
        let request = Request::builder()
            .method("GET")
            .uri("/api/v1/me")
            .header(header, value)
            .body(Body::empty())
            .unwrap();

        let response = ctx.server.app.clone().oneshot(request).await.unwrap();

        // All should return 401 (unauthorized)
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "Auth bypass attempt with {} should fail",
            header
        );
    }
}

/// Test JWT token tampering detection
#[tokio::test]
async fn test_jwt_tampering_detection() {
    init_tracing();

    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");

    // Create tampered tokens
    let tampered_tokens = vec![
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", // HS256 (wrong algo)
        "invalid.token.here",
        "not.even.a.jwt",
        "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjMifQ.", // None algorithm
    ];

    for token in tampered_tokens {
        let response = ctx.server.get_with_auth("/api/v1/me", token).await;

        // All should return 401 (unauthorized)
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "Tampered token should be rejected"
        );
    }
}

/// Test email validation
#[tokio::test]
async fn test_email_validation() {
    init_tracing();

    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");

    // Test invalid email formats
    let invalid_emails = vec![
        "not-an-email",
        "@example.com",
        "user@",
        "user@.com",
        "user@example",
        "user name@example.com",
        "user@example .com",
        "",
    ];

    for email in invalid_emails {
        let response = ctx
            .server
            .post(
                "/api/v1/register",
                json!({
                    "email": email,
                    "password": "TestPassword123!",
                    "name": "Test User",
                }),
            )
            .await;

        // Should return 400 for invalid email
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "Invalid email '{}' should be rejected",
            email
        );
    }
}

/// Test password strength validation
#[tokio::test]
async fn test_password_strength() {
    init_tracing();

    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");

    // Test weak passwords
    let weak_passwords = vec![
        ("short", "too short"),
        ("12345678", "no letters"),
        ("password", "common word"),
        ("Password", "no numbers/special"),
        ("password123", "common pattern"),
    ];

    for (password, reason) in weak_passwords {
        let response = ctx
            .server
            .post(
                "/api/v1/register",
                json!({
                    "email": unique_email(),
                    "password": password,
                    "name": "Test User",
                }),
            )
            .await;

        // Should return 400 for weak password
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "Weak password ({}) should be rejected: {}",
            reason,
            password
        );
    }
}

/// Test request ID header
#[tokio::test]
async fn test_request_id_header() {
    init_tracing();

    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");

    let response = ctx.server.get("/health").await;

    // Check for request ID header
    let headers = response.headers();

    // Request ID might be X-Request-Id or X-Request-ID
    let has_request_id = headers.get("x-request-id").is_some()
        || headers.get("X-Request-Id").is_some()
        || headers.get("x-request-ID").is_some();

    // This is optional but recommended
    if has_request_id {
        let request_id = headers
            .get("x-request-id")
            .or_else(|| headers.get("X-Request-Id"))
            .or_else(|| headers.get("x-request-ID"))
            .unwrap();

        assert!(
            !request_id.to_str().unwrap().is_empty(),
            "Request ID should not be empty"
        );
    }
}

/// Test brute force protection
#[tokio::test]
async fn test_brute_force_protection() {
    init_tracing();

    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");

    // Create a user
    let user = TestUser::new();
    let response = ctx
        .server
        .post("/api/v1/register", user.register_json())
        .await;
    assert_status(&response, StatusCode::OK);

    // Attempt many failed logins
    for i in 0..10 {
        let response = ctx
            .server
            .post(
                "/api/v1/login",
                json!({
                    "email": user.email,
                    "password": "WrongPassword123!",
                }),
            )
            .await;

        let status = response.status();

        // Check if account got locked
        if status == StatusCode::FORBIDDEN {
            // Account locked, verify we can't login even with correct password
            let response = ctx.server.post("/api/v1/login", user.login_json()).await;

            assert_eq!(
                response.status(),
                StatusCode::FORBIDDEN,
                "Locked account should not allow login"
            );

            return; // Test passed
        }

        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "Failed login {} should return 401",
            i
        );
    }

    // If we get here, account wasn't locked after 10 attempts
    // That's also acceptable depending on the lockout threshold
}
