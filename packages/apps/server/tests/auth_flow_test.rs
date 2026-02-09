//! End-to-end authentication flow tests
//!
//! Tests complete user journeys:
//! - Registration → Login → Logout
//! - Password reset flow
//! - Email verification
//! - Token refresh
//! - MFA enrollment

mod common;

use axum::http::StatusCode;
use common::*;
use serde_json::json;

/// Test health check endpoint
#[tokio::test]
async fn test_health_check() {
    init_tracing();

    // Skip if no database
    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");
    let response = ctx.server.get("/health").await;

    assert_status(&response, StatusCode::OK);

    let body = response_json(response).await;
    assert_eq!(body["status"], "healthy");
    assert!(body["version"].as_str().is_some());
}

/// Test user registration validation
#[tokio::test]
async fn test_register_validation() {
    init_tracing();

    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");

    // Test invalid email
    let response = ctx
        .server
        .post(
            "/api/v1/register",
            json!({
                "email": "invalid-email",
                "password": "TestPassword123!",
                "name": "Test User",
            }),
        )
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // Test short password (less than 12 characters)
    let response = ctx
        .server
        .post(
            "/api/v1/register",
            json!({
                "email": unique_email(),
                "password": "short",
                "name": "Test User",
            }),
        )
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // Test missing required fields
    let response = ctx
        .server
        .post(
            "/api/v1/register",
            json!({
                "email": unique_email(),
            }),
        )
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

/// Test complete registration and login flow
#[tokio::test]
async fn test_register_login_flow() {
    init_tracing();

    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");
    let user = TestUser::new();

    // 1. Register a new user
    let response = ctx
        .server
        .post("/api/v1/register", user.register_json())
        .await;
    assert_status(&response, StatusCode::OK);

    let body = response_json(response).await;
    let access_token = body["accessToken"].as_str().expect("Missing access token");
    let refresh_token = body["refreshToken"]
        .as_str()
        .expect("Missing refresh token");
    let user_id = body["user"]["id"].as_str().expect("Missing user id");

    assert!(!access_token.is_empty());
    assert!(!refresh_token.is_empty());
    assert_eq!(body["user"]["email"], user.email);
    assert!(!user_id.is_empty());

    // 2. Verify we can access protected endpoint with token
    let response = ctx.server.get_with_auth("/api/v1/me", access_token).await;
    assert_status(&response, StatusCode::OK);

    let body = response_json(response).await;
    assert_eq!(body["email"], user.email);

    // 3. Logout
    let response = ctx
        .server
        .post_with_auth("/api/v1/logout", json!({}), access_token)
        .await;
    assert_status(&response, StatusCode::OK);

    // 4. Verify token is invalidated (should get 401)
    let response = ctx.server.get_with_auth("/api/v1/me", access_token).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// Test login with invalid credentials
#[tokio::test]
async fn test_login_invalid_credentials() {
    init_tracing();

    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");
    let user = TestUser::new();

    // Try to login with non-existent user
    let response = ctx.server.post("/api/v1/login", user.login_json()).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // Register user first
    let _ = ctx
        .server
        .post("/api/v1/register", user.register_json())
        .await;

    // Try login with wrong password
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
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// Test password reset flow
#[tokio::test]
async fn test_password_reset_flow() {
    init_tracing();

    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");
    let user = TestUser::new();

    // 1. Register user
    let response = ctx
        .server
        .post("/api/v1/register", user.register_json())
        .await;
    assert_status(&response, StatusCode::OK);

    // 2. Request password reset
    let response = ctx
        .server
        .post(
            "/api/v1/forgot-password",
            json!({
                "email": user.email,
            }),
        )
        .await;
    assert_status(&response, StatusCode::OK);

    let body = response_json(response).await;
    assert!(body["message"].as_str().unwrap().contains("sent"));

    // Note: In a real test environment with email capture, we would:
    // 3. Get reset token from email
    // 4. Reset password with token
    // 5. Verify old password no longer works
    // 6. Verify new password works

    // For now, we test the endpoint exists and returns expected format
}

/// Test password reset with non-existent email (should not reveal)
#[tokio::test]
async fn test_password_reset_nonexistent_email() {
    init_tracing();

    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");

    // Request password reset for non-existent email should still return success
    // to prevent email enumeration attacks
    let response = ctx
        .server
        .post(
            "/api/v1/forgot-password",
            json!({
                "email": "nonexistent@example.com",
            }),
        )
        .await;

    // Should return OK to prevent email enumeration
    assert_status(&response, StatusCode::OK);

    let body = response_json(response).await;
    assert!(body["message"].as_str().unwrap().contains("sent"));
}

/// Test token refresh
#[tokio::test]
async fn test_token_refresh() {
    init_tracing();

    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");
    let (_, _, refresh_token) = ctx
        .create_user_and_login()
        .await
        .expect("Failed to create user");

    // Use refresh token to get new access token
    let response = ctx
        .server
        .post(
            "/api/v1/refresh",
            json!({
                "refreshToken": refresh_token,
            }),
        )
        .await;

    assert_status(&response, StatusCode::OK);

    let body = response_json(response).await;
    let new_access_token = body["accessToken"].as_str().expect("Missing access token");
    let new_refresh_token = body["refreshToken"]
        .as_str()
        .expect("Missing refresh token");

    assert!(!new_access_token.is_empty());
    assert!(!new_refresh_token.is_empty());

    // Verify new access token works
    let response = ctx
        .server
        .get_with_auth("/api/v1/me", new_access_token)
        .await;
    assert_status(&response, StatusCode::OK);
}

/// Test refresh with invalid token
#[tokio::test]
async fn test_refresh_invalid_token() {
    init_tracing();

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
            "/api/v1/refresh",
            json!({
                "refreshToken": "invalid-token",
            }),
        )
        .await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// Test email verification flow
#[tokio::test]
async fn test_email_verification_flow() {
    init_tracing();

    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");
    let user = TestUser::new();

    // 1. Register user
    let response = ctx
        .server
        .post("/api/v1/register", user.register_json())
        .await;
    assert_status(&response, StatusCode::OK);

    // Note: With dev_auto_verify_email enabled, the email should already be verified
    // In production tests, you would:
    // 2. Verify user is unverified initially
    // 3. Get verification token from email
    // 4. Verify email with token
    // 5. Verify user is now verified

    // Test the verify-email endpoint exists
    let response = ctx
        .server
        .post(
            "/api/v1/verify-email",
            json!({
                "token": "invalid-token",
            }),
        )
        .await;

    // Should return 400 for invalid token
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

/// Test rate limiting on auth endpoints
#[tokio::test]
async fn test_auth_rate_limiting() {
    init_tracing();

    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");

    // Make multiple rapid login requests with invalid credentials
    for _ in 0..10 {
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

        // We expect either 401 (unauthorized) or 429 (rate limited)
        let status = response.status();
        assert!(
            status == StatusCode::UNAUTHORIZED || status == StatusCode::TOO_MANY_REQUESTS,
            "Expected 401 or 429, got {:?}",
            status
        );

        // If we hit rate limit, stop the test
        if status == StatusCode::TOO_MANY_REQUESTS {
            break;
        }
    }
}

/// Test concurrent session handling
#[tokio::test]
async fn test_concurrent_sessions() {
    init_tracing();

    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");
    let user = TestUser::new();

    // Register user
    let response = ctx
        .server
        .post("/api/v1/register", user.register_json())
        .await;
    assert_status(&response, StatusCode::OK);

    // Login from "Device A"
    let response_a = ctx.server.post("/api/v1/login", user.login_json()).await;
    let body_a = response_json(response_a).await;
    let token_a = body_a["accessToken"].as_str().unwrap().to_string();

    // Login from "Device B"
    let response_b = ctx.server.post("/api/v1/login", user.login_json()).await;
    let body_b = response_json(response_b).await;
    let token_b = body_b["accessToken"].as_str().unwrap().to_string();

    // Both tokens should work
    let response = ctx.server.get_with_auth("/api/v1/me", &token_a).await;
    assert_status(&response, StatusCode::OK);

    let response = ctx.server.get_with_auth("/api/v1/me", &token_b).await;
    assert_status(&response, StatusCode::OK);

    // Logout from Device A
    let response = ctx
        .server
        .post_with_auth("/api/v1/logout", json!({}), &token_a)
        .await;
    assert_status(&response, StatusCode::OK);

    // Token A should no longer work
    let response = ctx.server.get_with_auth("/api/v1/me", &token_a).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // Token B should still work
    let response = ctx.server.get_with_auth("/api/v1/me", &token_b).await;
    assert_status(&response, StatusCode::OK);
}

/// Test magic link authentication
#[tokio::test]
async fn test_magic_link_flow() {
    init_tracing();

    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");
    let user = TestUser::new();

    // 1. Register user first
    let response = ctx
        .server
        .post("/api/v1/register", user.register_json())
        .await;
    assert_status(&response, StatusCode::OK);

    // 2. Request magic link
    let response = ctx
        .server
        .post(
            "/api/v1/magic-link",
            json!({
                "email": user.email,
            }),
        )
        .await;

    assert_status(&response, StatusCode::OK);

    let body = response_json(response).await;
    assert!(body["message"].as_str().unwrap().contains("sent"));

    // Note: In a real test, you would capture the magic link from email
    // and test the verify endpoint

    // 3. Test verify magic link with invalid token
    let response = ctx
        .server
        .post(
            "/api/v1/magic-link/verify",
            json!({
                "token": "invalid-token",
            }),
        )
        .await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// Test magic link for non-existent user (should not reveal)
#[tokio::test]
async fn test_magic_link_nonexistent_user() {
    init_tracing();

    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");

    // Request magic link for non-existent user should still return success
    let response = ctx
        .server
        .post(
            "/api/v1/magic-link",
            json!({
                "email": "nonexistent@example.com",
            }),
        )
        .await;

    // Should return OK to prevent email enumeration
    assert_status(&response, StatusCode::OK);

    let body = response_json(response).await;
    assert!(body["message"].as_str().unwrap().contains("sent"));
}

/// Test logout from all devices
#[tokio::test]
async fn test_logout_all_devices() {
    init_tracing();

    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");
    let user = TestUser::new();

    // Register and get initial token
    let response = ctx
        .server
        .post("/api/v1/register", user.register_json())
        .await;
    let body = response_json(response).await;
    let token_1 = body["accessToken"].as_str().unwrap().to_string();

    // Create multiple sessions by logging in multiple times
    let response = ctx.server.post("/api/v1/login", user.login_json()).await;
    let body = response_json(response).await;
    let token_2 = body["accessToken"].as_str().unwrap().to_string();

    // Verify both tokens work
    let response = ctx.server.get_with_auth("/api/v1/me", &token_1).await;
    assert_status(&response, StatusCode::OK);

    let response = ctx.server.get_with_auth("/api/v1/me", &token_2).await;
    assert_status(&response, StatusCode::OK);

    // Note: The current implementation doesn't have a "logout all" endpoint
    // for the current user, but admin can revoke all sessions for any user.
    // This test documents the expected behavior.
}

/// Test protected endpoint access
#[tokio::test]
async fn test_protected_endpoint_access() {
    init_tracing();

    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");

    // 1. Access without token - should 401
    let response = ctx.server.get("/api/v1/me").await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // 2. Access with invalid token - should 401
    let response = ctx
        .server
        .get_with_auth("/api/v1/me", "invalid-token")
        .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // 3. Create user and get valid token
    let (user, token) = ctx
        .create_user_and_login()
        .await
        .map(|(u, t, _)| (u, t))
        .expect("Failed to create user");

    // 4. Access with valid token - should 200
    let response = ctx.server.get_with_auth("/api/v1/me", &token).await;
    assert_status(&response, StatusCode::OK);

    let body = response_json(response).await;
    assert_eq!(body["email"], user.email);

    // 5. Logout
    let response = ctx
        .server
        .post_with_auth("/api/v1/logout", json!({}), &token)
        .await;
    assert_status(&response, StatusCode::OK);

    // 6. Access after logout - should 401
    let response = ctx.server.get_with_auth("/api/v1/me", &token).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// Test duplicate registration (email already exists)
#[tokio::test]
async fn test_duplicate_registration() {
    init_tracing();

    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");
    let user = TestUser::new();

    // First registration should succeed
    let response = ctx
        .server
        .post("/api/v1/register", user.register_json())
        .await;
    assert_status(&response, StatusCode::OK);

    // Second registration with same email should fail
    let response = ctx
        .server
        .post("/api/v1/register", user.register_json())
        .await;
    assert_eq!(response.status(), StatusCode::CONFLICT);

    let body = response_json(response).await;
    assert!(body["error"]["message"]
        .as_str()
        .unwrap()
        .to_lowercase()
        .contains("exists"));
}

/// Test get current user profile
#[tokio::test]
async fn test_get_current_user() {
    init_tracing();

    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");
    let (user, token) = ctx
        .create_user_and_login()
        .await
        .map(|(u, t, _)| (u, t))
        .expect("Failed to create user");

    let response = ctx.server.get_with_auth("/api/v1/me", &token).await;
    assert_status(&response, StatusCode::OK);

    let body = response_json(response).await;
    assert_eq!(body["email"], user.email);
    assert!(body["id"].as_str().is_some());
    assert!(body["emailVerified"].is_boolean());
}

/// Test change password
#[tokio::test]
async fn test_change_password() {
    init_tracing();

    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");
    let (user, token) = ctx
        .create_user_and_login()
        .await
        .map(|(u, t, _)| (u, t))
        .expect("Failed to create user");

    // Change password
    let new_password = "NewPassword456!";
    let response = ctx
        .server
        .post_with_auth(
            "/api/v1/me/password",
            json!({
                "current_password": user.password,
                "new_password": new_password,
            }),
            &token,
        )
        .await;

    assert_status(&response, StatusCode::OK);

    // Old password should no longer work
    let response = ctx
        .server
        .post(
            "/api/v1/login",
            json!({
                "email": user.email,
                "password": user.password,
            }),
        )
        .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // New password should work
    let response = ctx
        .server
        .post(
            "/api/v1/login",
            json!({
                "email": user.email,
                "password": new_password,
            }),
        )
        .await;
    assert_status(&response, StatusCode::OK);
}

/// Test change password with wrong current password
#[tokio::test]
async fn test_change_password_wrong_current() {
    init_tracing();

    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");
    let (_, token, _) = ctx
        .create_user_and_login()
        .await
        .expect("Failed to create user");

    // Try to change password with wrong current password
    let response = ctx
        .server
        .post_with_auth(
            "/api/v1/me/password",
            json!({
                "current_password": "WrongPassword123!",
                "new_password": "NewPassword456!",
            }),
            &token,
        )
        .await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// Test update user profile
#[tokio::test]
async fn test_update_profile() {
    init_tracing();

    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");
    let (user, token) = ctx
        .create_user_and_login()
        .await
        .map(|(u, t, _)| (u, t))
        .expect("Failed to create user");

    // Update profile
    let new_name = "Updated Name";
    let response = ctx
        .server
        .patch_with_auth(
            "/api/v1/me",
            json!({
                "name": new_name,
            }),
            &token,
        )
        .await;

    assert_status(&response, StatusCode::OK);

    let body = response_json(response).await;
    assert_eq!(body["name"], new_name);
    assert_eq!(body["email"], user.email);
}

/// Test delete user account
#[tokio::test]
async fn test_delete_account() {
    init_tracing();

    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");
    let (user, token) = ctx
        .create_user_and_login()
        .await
        .map(|(u, t, _)| (u, t))
        .expect("Failed to create user");

    // Delete account
    let response = ctx.server.delete_with_auth("/api/v1/me", &token).await;
    assert_status(&response, StatusCode::OK);

    // Should no longer be able to login
    let response = ctx
        .server
        .post(
            "/api/v1/login",
            json!({
                "email": user.email,
                "password": user.password,
            }),
        )
        .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
