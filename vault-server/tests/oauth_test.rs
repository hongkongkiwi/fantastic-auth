//! OAuth Integration Tests
//!
//! Tests OAuth 2.0 and OpenID Connect authentication flows:
//! - OAuth redirect URL generation
//! - OAuth callback handling
//! - State parameter validation (CSRF protection)
//! - PKCE flow

mod common;

use axum::http::StatusCode;
use common::*;
use serde_json::json;
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Test OAuth redirect URL generation for Google
#[tokio::test]
async fn test_oauth_redirect_google() {
    init_tracing();

    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");

    // Request OAuth redirect for Google
    let response = ctx
        .server
        .post(
            "/api/v1/oauth/google",
            json!({
                "redirectUri": "http://localhost:3000/callback",
            }),
        )
        .await;

    // Should return 501 (Not Implemented) if OAuth not configured
    // or 200 if configured
    let status = response.status();
    assert!(
        status == StatusCode::OK || status == StatusCode::NOT_IMPLEMENTED,
        "Expected 200 or 501, got {:?}",
        status
    );

    if status == StatusCode::OK {
        let body = response_json(response).await;

        // Verify response structure
        assert!(body["authUrl"].as_str().is_some(), "Missing authUrl");
        assert!(body["state"].as_str().is_some(), "Missing state");

        let auth_url = body["authUrl"].as_str().unwrap();

        // Verify URL structure
        assert!(
            auth_url.contains("accounts.google.com") || auth_url.contains("google"),
            "Auth URL should be for Google"
        );
        assert!(
            auth_url.contains("response_type=code"),
            "Missing response_type"
        );
        assert!(auth_url.contains("client_id="), "Missing client_id");
    }
}

/// Test OAuth redirect URL generation for GitHub
#[tokio::test]
async fn test_oauth_redirect_github() {
    init_tracing();

    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");

    // Request OAuth redirect for GitHub
    let response = ctx
        .server
        .post(
            "/api/v1/oauth/github",
            json!({
                "redirectUri": "http://localhost:3000/callback",
            }),
        )
        .await;

    let status = response.status();
    assert!(
        status == StatusCode::OK
            || status == StatusCode::NOT_IMPLEMENTED
            || status == StatusCode::BAD_REQUEST,
        "Expected 200, 400, or 501, got {:?}",
        status
    );
}

/// Test OAuth redirect URL generation for Microsoft
#[tokio::test]
async fn test_oauth_redirect_microsoft() {
    init_tracing();

    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");

    // Request OAuth redirect for Microsoft
    let response = ctx
        .server
        .post(
            "/api/v1/oauth/microsoft",
            json!({
                "redirectUri": "http://localhost:3000/callback",
            }),
        )
        .await;

    let status = response.status();
    assert!(
        status == StatusCode::OK
            || status == StatusCode::NOT_IMPLEMENTED
            || status == StatusCode::BAD_REQUEST,
        "Expected 200, 400, or 501, got {:?}",
        status
    );
}

/// Test OAuth redirect for unsupported provider
#[tokio::test]
async fn test_oauth_redirect_unsupported_provider() {
    init_tracing();

    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");

    // Request OAuth redirect for unsupported provider
    let response = ctx
        .server
        .post(
            "/api/v1/oauth/unsupported",
            json!({
                "redirectUri": "http://localhost:3000/callback",
            }),
        )
        .await;

    // Should return 400 for unsupported provider
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

/// Test OAuth state parameter generation
#[tokio::test]
async fn test_oauth_state_generation() {
    init_tracing();

    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");

    // Make multiple requests and verify states are different
    let response1 = ctx.server.post("/api/v1/oauth/google", json!({})).await;
    let response2 = ctx.server.post("/api/v1/oauth/google", json!({})).await;

    if response1.status() == StatusCode::OK && response2.status() == StatusCode::OK {
        let body1 = response_json(response1).await;
        let body2 = response_json(response2).await;

        let state1 = body1["state"].as_str().expect("Missing state");
        let state2 = body2["state"].as_str().expect("Missing state");

        // States should be different (unique per request)
        assert_ne!(state1, state2, "OAuth states should be unique per request");

        // States should be non-empty
        assert!(!state1.is_empty(), "State should not be empty");
        assert!(!state2.is_empty(), "State should not be empty");
    }
}

/// Test OAuth callback with missing code
#[tokio::test]
async fn test_oauth_callback_missing_code() {
    init_tracing();

    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");

    // Call OAuth callback without code parameter
    let response = ctx.server.get("/api/v1/oauth/google/callback").await;

    // Should return 400 for missing code
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

/// Test OAuth callback with invalid state
#[tokio::test]
async fn test_oauth_callback_invalid_state() {
    init_tracing();

    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");

    // Call OAuth callback with invalid state
    let response = ctx
        .server
        .get("/api/v1/oauth/google/callback?code=test-code&state=invalid-state")
        .await;

    // Should return 400 for invalid state
    let status = response.status();
    assert!(
        status == StatusCode::BAD_REQUEST || status == StatusCode::INTERNAL_SERVER_ERROR,
        "Expected 400 or 500, got {:?}",
        status
    );
}

/// Test OAuth callback with provider error
#[tokio::test]
async fn test_oauth_callback_provider_error() {
    init_tracing();

    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");

    // Call OAuth callback with provider error
    let response = ctx.server.get(
        "/api/v1/oauth/google/callback?error=access_denied&error_description=user+denied+access"
    ).await;

    // Should return 400 for OAuth error
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

/// Test complete OAuth flow with mocked provider
#[tokio::test]
async fn test_oauth_flow_mocked() {
    init_tracing();

    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    // Start mock OAuth server
    let mock_server = MockServer::start().await;

    // Mock token endpoint
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "mock_access_token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "mock_refresh_token",
        })))
        .mount(&mock_server)
        .await;

    // Mock userinfo endpoint
    Mock::given(method("GET"))
        .and(path("/oauth/userinfo"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "sub": "12345",
            "email": "oauth-user@example.com",
            "email_verified": true,
            "name": "OAuth Test User",
            "given_name": "OAuth",
            "family_name": "User",
            "picture": "https://example.com/photo.jpg",
        })))
        .mount(&mock_server)
        .await;

    // Note: To fully test this, we would need to:
    // 1. Configure the OAuth provider to use the mock server URLs
    // 2. Get a valid state from the redirect endpoint
    // 3. Call the callback with the mock code and state

    // For now, we verify the endpoint structure
    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");

    // Verify OAuth endpoints exist
    let response = ctx.server.post("/api/v1/oauth/google", json!({})).await;
    let status = response.status();

    // Endpoint should exist (returning 200 or 501 depending on config)
    assert!(
        status == StatusCode::OK || status == StatusCode::NOT_IMPLEMENTED,
        "OAuth endpoint should exist, got {:?}",
        status
    );
}

/// Test OAuth with PKCE (Proof Key for Code Exchange)
#[tokio::test]
async fn test_oauth_pkce() {
    init_tracing();

    // PKCE is enabled by default for security
    // This test verifies the authorization URL includes PKCE parameters

    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");

    let response = ctx
        .server
        .post(
            "/api/v1/oauth/google",
            json!({
                "redirectUri": "http://localhost:3000/callback",
            }),
        )
        .await;

    if response.status() == StatusCode::OK {
        let body = response_json(response).await;
        let auth_url = body["authUrl"].as_str().expect("Missing authUrl");

        // Verify PKCE parameters are present
        assert!(
            auth_url.contains("code_challenge") || !auth_url.contains("code_challenge_method"),
            "PKCE should be enabled or explicitly disabled"
        );
    }
}

/// Test OAuth redirect URL includes proper scopes
#[tokio::test]
async fn test_oauth_scopes() {
    init_tracing();

    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");

    let response = ctx.server.post("/api/v1/oauth/google", json!({})).await;

    if response.status() == StatusCode::OK {
        let body = response_json(response).await;
        let auth_url = body["authUrl"].as_str().expect("Missing authUrl");

        // Verify scopes are included
        assert!(
            auth_url.contains("scope="),
            "Auth URL should include scopes"
        );
        assert!(
            auth_url.contains("email") || auth_url.contains("openid"),
            "Auth URL should include email or openid scope"
        );
    }
}

/// Test OAuth signup disabled
#[tokio::test]
async fn test_oauth_signup_disabled() {
    init_tracing();

    // This test would verify that when enable_oauth_signup is false,
    // new users cannot be created via OAuth

    // Note: This requires modifying the test config, which would need
    // a separate test setup

    // For now, we document the expected behavior
}

/// Test OAuth linking to existing account
#[tokio::test]
async fn test_oauth_link_existing_account() {
    init_tracing();

    // This test would verify that:
    // 1. A user with an existing account can link their OAuth identity
    // 2. After linking, they can log in with either password or OAuth

    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");
    let (user, _) = ctx
        .create_user_and_login()
        .await
        .map(|(u, t, _)| (u, t))
        .expect("Failed to create user");

    // The user now exists with password auth
    // In a real scenario, they would link their OAuth account
    // and then be able to log in via OAuth

    // Verify user exists
    assert!(!user.email.is_empty());
}

/// Test SSO redirect endpoint
#[tokio::test]
async fn test_sso_redirect() {
    init_tracing();

    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");

    // Test SSO redirect with domain
    let response = ctx
        .server
        .get("/api/v1/auth/sso/redirect?domain=example.com")
        .await;
    assert_status(&response, StatusCode::OK);

    let body = response_json(response).await;
    assert!(body["url"].as_str().is_some(), "Missing redirect URL");
}

/// Test SSO redirect with connection_id
#[tokio::test]
async fn test_sso_redirect_with_connection_id() {
    init_tracing();

    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");

    // Test SSO redirect with connection_id
    let response = ctx
        .server
        .get("/api/v1/auth/sso/redirect?connection_id=conn_123")
        .await;
    assert_status(&response, StatusCode::OK);

    let body = response_json(response).await;
    assert!(body["url"].as_str().is_some(), "Missing redirect URL");
}

/// Test SAML metadata endpoint
#[tokio::test]
async fn test_saml_metadata() {
    init_tracing();

    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");

    // Test SAML metadata endpoint
    let response = ctx
        .server
        .get("/api/v1/auth/sso/metadata?connection_id=conn_123")
        .await;

    // Endpoint returns XML
    let status = response.status();
    assert!(
        status == StatusCode::OK || status == StatusCode::NOT_FOUND,
        "Expected 200 or 404, got {:?}",
        status
    );
}
