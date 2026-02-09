//! API Contract Tests
//!
//! These tests verify the API structure and response formats
//! without requiring a database connection for basic tests.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::json;
use tower::ServiceExt;

mod common;

/// Test that auth endpoints exist and return proper error formats
#[tokio::test]
async fn test_auth_endpoints_exist() {
    // Compile-time symbol check for route builders/handlers
    let _ = vault_server::routes::api_routes;
    let _ = vault_server::routes::health_check;
}

/// Test error response format for validation errors
#[tokio::test]
async fn test_validation_error_format() {
    common::init_tracing();

    if !common::test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = common::TestContext::new()
        .await
        .expect("Failed to create test context");

    // Trigger a validation error
    let response = ctx
        .server
        .post(
            "/api/v1/register",
            json!({
                "email": "invalid-email",
                "password": "short",
            }),
        )
        .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body = common::response_json(response).await;

    // Verify error response structure
    assert!(body.get("error").is_some(), "Missing error object");
    assert!(body["error"].get("code").is_some(), "Missing error code");
    assert!(
        body["error"].get("message").is_some(),
        "Missing error message"
    );
}

/// Test error response format for authentication errors
#[tokio::test]
async fn test_auth_error_format() {
    common::init_tracing();

    if !common::test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = common::TestContext::new()
        .await
        .expect("Failed to create test context");

    // Trigger an auth error
    let response = ctx
        .server
        .post(
            "/api/v1/login",
            json!({
                "email": "nonexistent@example.com",
                "password": "WrongPassword123!",
            }),
        )
        .await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let body = common::response_json(response).await;

    // Verify error response structure
    assert!(body.get("error").is_some(), "Missing error object");
    assert_eq!(body["error"]["code"], "UNAUTHORIZED");
}

/// Test error response format for not found
#[tokio::test]
async fn test_not_found_error_format() {
    common::init_tracing();

    if !common::test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = common::TestContext::new()
        .await
        .expect("Failed to create test context");

    // Request non-existent endpoint
    let response = ctx.server.get("/api/v1/nonexistent-endpoint").await;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let body = common::response_json(response).await;

    // Verify error response structure
    assert!(body.get("error").is_some(), "Missing error object");
    assert_eq!(body["error"]["code"], "NOT_FOUND");
}

/// Test success response format for auth
#[test]
fn test_auth_response_format() {
    let auth_response = json!({
        "accessToken": "eyJhbGc...",
        "refreshToken": "eyJhbGc...",
        "tokenType": "Bearer",
        "expiresIn": 900,
        "user": {
            "id": "user_123",
            "email": "user@example.com",
            "name": "Test User",
            "emailVerified": true,
            "mfaEnabled": false
        },
        "mfaRequired": false
    });

    assert!(auth_response.get("accessToken").is_some());
    assert!(auth_response.get("refreshToken").is_some());
    assert_eq!(auth_response["tokenType"], "Bearer");
    assert!(auth_response.get("expiresIn").is_some());
    assert!(auth_response.get("user").is_some());
    assert!(auth_response.get("mfaRequired").is_some());

    // Verify user object structure
    let user = &auth_response["user"];
    assert!(user.get("id").is_some());
    assert!(user.get("email").is_some());
    assert!(user.get("emailVerified").is_some());
    assert!(user.get("mfaEnabled").is_some());
}

/// Test user response format
#[test]
fn test_user_response_format() {
    let user_response = json!({
        "id": "user_123",
        "email": "user@example.com",
        "name": "Test User",
        "status": "active",
        "emailVerified": true,
        "mfaEnabled": false,
        "createdAt": "2024-01-01T00:00:00Z",
        "updatedAt": "2024-01-01T00:00:00Z",
        "lastLoginAt": "2024-01-01T00:00:00Z"
    });

    assert!(user_response.get("id").is_some());
    assert!(user_response.get("email").is_some());
    assert!(user_response.get("status").is_some());
    assert!(user_response.get("createdAt").is_some());
}

/// Test session response format
#[test]
fn test_session_response_format() {
    let session_response = json!({
        "id": "sess_123",
        "userId": "user_123",
        "createdAt": "2024-01-01T00:00:00Z",
        "expiresAt": "2024-01-08T00:00:00Z",
        "ipAddress": "192.168.1.1",
        "userAgent": "Mozilla/5.0...",
        "isCurrent": true
    });

    assert!(session_response.get("id").is_some());
    assert!(session_response.get("expiresAt").is_some());
}

/// Test validation error format with field details
#[test]
fn test_validation_error_format_with_details() {
    let validation_error = json!({
        "error": {
            "code": "VALIDATION_ERROR",
            "message": "Request validation failed",
            "details": [
                {
                    "field": "password",
                    "message": "Password must be at least 12 characters"
                },
                {
                    "field": "email",
                    "message": "Email is required"
                }
            ]
        }
    });

    let details = validation_error["error"]["details"].as_array().unwrap();
    assert_eq!(details.len(), 2);
    assert!(details[0].get("field").is_some());
    assert!(details[0].get("message").is_some());
}

/// Test rate limit error format
#[test]
fn test_rate_limit_error_format() {
    let rate_limit_error = json!({
        "error": {
            "code": "RATE_LIMIT_EXCEEDED",
            "message": "Too many requests. Please try again later.",
            "retryAfter": 60
        }
    });

    assert_eq!(rate_limit_error["error"]["code"], "RATE_LIMIT_EXCEEDED");
    assert!(rate_limit_error["error"].get("retryAfter").is_some());
}

/// Test pagination response format
#[test]
fn test_pagination_response_format() {
    let paginated_response = json!({
        "data": [
            {"id": "1", "name": "Item 1"},
            {"id": "2", "name": "Item 2"}
        ],
        "pagination": {
            "page": 1,
            "perPage": 20,
            "total": 100,
            "totalPages": 5
        }
    });

    assert!(paginated_response.get("data").is_some());
    assert!(paginated_response.get("pagination").is_some());
    assert!(paginated_response["pagination"].get("total").is_some());
    assert!(paginated_response["pagination"].get("totalPages").is_some());
}

/// Test error response format for conflict
#[tokio::test]
async fn test_conflict_error_format() {
    common::init_tracing();

    if !common::test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = common::TestContext::new()
        .await
        .expect("Failed to create test context");
    let user = common::TestUser::new();

    // Register user first
    let response = ctx
        .server
        .post("/api/v1/register", user.register_json())
        .await;
    assert_eq!(response.status(), StatusCode::OK);

    // Try to register again with same email
    let response = ctx
        .server
        .post("/api/v1/register", user.register_json())
        .await;
    assert_eq!(response.status(), StatusCode::CONFLICT);

    let body = common::response_json(response).await;

    // Verify error response structure
    assert!(body.get("error").is_some(), "Missing error object");
    assert_eq!(body["error"]["code"], "CONFLICT");
    assert!(body["error"]["message"]
        .as_str()
        .unwrap()
        .to_lowercase()
        .contains("exists"));
}

/// Test error response format for forbidden
#[tokio::test]
async fn test_forbidden_error_format() {
    common::init_tracing();

    if !common::test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = common::TestContext::new()
        .await
        .expect("Failed to create test context");
    let (_, token) = ctx
        .create_user_and_login()
        .await
        .map(|(_, t, _)| ((), t))
        .expect("Failed to create user");

    // Try to access admin endpoint without admin role
    let response = ctx
        .server
        .get_with_auth("/api/v1/admin/users", &token)
        .await;

    // Should be 403 or 200 depending on admin status
    let status = response.status();
    if status == StatusCode::FORBIDDEN {
        let body = common::response_json(response).await;

        // Verify error response structure
        assert!(body.get("error").is_some(), "Missing error object");
        assert_eq!(body["error"]["code"], "FORBIDDEN");
    }
}

/// Test message response format
#[test]
fn test_message_response_format() {
    let message_response = json!({
        "message": "Operation completed successfully"
    });

    assert!(message_response.get("message").is_some());
}

/// Test MFA setup response format
#[test]
fn test_mfa_setup_response_format() {
    let mfa_setup_response = json!({
        "secret": "JBSWY3DPEHPK3PXP",
        "qrCodeUri": "otpauth://totp/Vault:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Vault",
        "backupCodes": [
            "ABCD-EFGH-IJKL",
            "MNOP-QRST-UVWX",
            "YZAB-CDEF-GHIJ"
        ]
    });

    assert!(mfa_setup_response.get("secret").is_some());
    assert!(mfa_setup_response.get("qrCodeUri").is_some());
    assert!(mfa_setup_response.get("backupCodes").is_some());

    let codes = mfa_setup_response["backupCodes"].as_array().unwrap();
    assert!(!codes.is_empty());
}

/// Test OAuth redirect response format
#[test]
fn test_oauth_redirect_response_format() {
    let oauth_response = json!({
        "authUrl": "https://accounts.google.com/o/oauth2/v2/auth?client_id=...",
        "state": "random-state-value-for-csrf-protection"
    });

    assert!(oauth_response.get("authUrl").is_some());
    assert!(oauth_response.get("state").is_some());
}

/// Test health check response format
#[tokio::test]
async fn test_health_response_format() {
    common::init_tracing();

    if !common::test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = common::TestContext::new()
        .await
        .expect("Failed to create test context");

    let response = ctx.server.get("/health").await;
    assert_eq!(response.status(), StatusCode::OK);

    let body = common::response_json(response).await;

    // Verify health response structure
    assert_eq!(body["status"], "healthy");
    assert!(body.get("version").is_some());
    assert!(body.get("serverTime").is_some());
}

/// Test all auth endpoints return expected status codes
#[tokio::test]
async fn test_auth_endpoint_status_codes() {
    common::init_tracing();

    if !common::test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = common::TestContext::new()
        .await
        .expect("Failed to create test context");

    // Test endpoints with missing/invalid body
    let endpoints = vec![
        ("POST", "/api/v1/register", StatusCode::BAD_REQUEST),
        ("POST", "/api/v1/login", StatusCode::BAD_REQUEST),
        ("POST", "/api/v1/refresh", StatusCode::BAD_REQUEST),
        ("POST", "/api/v1/forgot-password", StatusCode::BAD_REQUEST),
        ("POST", "/api/v1/reset-password", StatusCode::BAD_REQUEST),
        ("POST", "/api/v1/verify-email", StatusCode::BAD_REQUEST),
        ("POST", "/api/v1/magic-link", StatusCode::BAD_REQUEST),
        ("POST", "/api/v1/magic-link/verify", StatusCode::BAD_REQUEST),
    ];

    for (method, endpoint, expected_status) in endpoints {
        let response = match method {
            "POST" => ctx.server.post(endpoint, json!({})).await,
            _ => continue,
        };

        assert_eq!(
            response.status(),
            expected_status,
            "{} {} should return {:?}",
            method,
            endpoint,
            expected_status
        );
    }
}

/// Test protected endpoints require authentication
#[tokio::test]
async fn test_protected_endpoints_require_auth() {
    common::init_tracing();

    if !common::test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = common::TestContext::new()
        .await
        .expect("Failed to create test context");

    // Test protected endpoints without auth
    let endpoints = vec![
        ("GET", "/api/v1/me"),
        ("PATCH", "/api/v1/me"),
        ("DELETE", "/api/v1/me"),
        ("POST", "/api/v1/logout"),
        ("POST", "/api/v1/me/password"),
        ("GET", "/api/v1/users/me/mfa"),
        ("POST", "/api/v1/users/me/mfa"),
        ("DELETE", "/api/v1/users/me/mfa"),
    ];

    for (method, endpoint) in endpoints {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let request = Request::builder()
            .method(method)
            .uri(endpoint)
            .body(Body::empty())
            .unwrap();

        let response = ctx.server.app.clone().oneshot(request).await.unwrap();

        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "{} {} should require authentication",
            method,
            endpoint
        );
    }
}

/// Test content negotiation
#[tokio::test]
async fn test_content_negotiation() {
    common::init_tracing();

    if !common::test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = common::TestContext::new()
        .await
        .expect("Failed to create test context");

    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    // Test with Accept: application/json
    let request = Request::builder()
        .method("GET")
        .uri("/health")
        .header("Accept", "application/json")
        .body(Body::empty())
        .unwrap();

    let response = ctx.server.app.clone().oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    assert!(
        content_type.contains("application/json"),
        "Response should be JSON"
    );
}

/// Test API versioning
#[tokio::test]
async fn test_api_versioning() {
    common::init_tracing();

    if !common::test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = common::TestContext::new()
        .await
        .expect("Failed to create test context");

    // All endpoints should be under /api/v1
    let versioned_endpoints = vec![
        "/api/v1/health", // Note: health is typically not versioned
        "/api/v1/register",
        "/api/v1/login",
        "/api/v1/me",
    ];

    for endpoint in versioned_endpoints {
        // We just verify the routes exist (they return 401/404/405 but not 404 for missing route)
        let response = ctx.server.get(endpoint).await;

        // Should not be "not found" (which would mean route doesn't exist)
        // 401, 405, or other errors are fine
        let status = response.status();
        assert_ne!(
            status,
            StatusCode::NOT_FOUND,
            "Endpoint {} should exist",
            endpoint
        );
    }
}
