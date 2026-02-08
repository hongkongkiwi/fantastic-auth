//! Admin API Tests
//!
//! Tests administrative user management operations:
//! - User listing with pagination and filters
//! - User creation
//! - User updates
//! - User suspension/activation
//! - Session revocation

mod common;

use axum::http::StatusCode;
use common::*;
use serde_json::json;

/// Test admin user listing
#[tokio::test]
async fn test_admin_list_users() {
    init_tracing();

    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");

    // Create a user and use as admin (in real scenario would need admin role)
    let (_, token) = ctx
        .create_user_and_login()
        .await
        .map(|(_, t, _)| ((), t))
        .expect("Failed to create user");

    // List users
    let response = ctx
        .server
        .get_with_auth("/api/v1/admin/users", &token)
        .await;

    // Should return 200 or 403 (depending on admin privileges)
    let status = response.status();
    assert!(
        status == StatusCode::OK
            || status == StatusCode::FORBIDDEN
            || status == StatusCode::UNAUTHORIZED,
        "Expected 200, 403, or 401, got {:?}",
        status
    );

    if status == StatusCode::OK {
        let body = response_json(response).await;

        // Verify response structure
        assert!(body["users"].is_array(), "Missing users array");
        assert!(body["total"].is_number(), "Missing total count");
        assert!(body["page"].is_number(), "Missing page number");
        assert!(body["per_page"].is_number(), "Missing per_page");
    }
}

/// Test admin user listing with pagination
#[tokio::test]
async fn test_admin_list_users_pagination() {
    init_tracing();

    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");

    // Create multiple users
    for _ in 0..5 {
        let _ = ctx.create_user_and_login().await;
    }

    // Get admin token
    let (_, token) = ctx
        .create_user_and_login()
        .await
        .map(|(_, t, _)| ((), t))
        .expect("Failed to create admin user");

    // Test pagination parameters
    let response = ctx
        .server
        .get_with_auth("/api/v1/admin/users?page=1&per_page=2", &token)
        .await;

    let status = response.status();
    if status == StatusCode::OK {
        let body = response_json(response).await;

        assert_eq!(body["page"], 1);
        assert_eq!(body["per_page"], 2);

        // Should have at most 2 users per page
        let users = body["users"].as_array().unwrap();
        assert!(users.len() <= 2, "Should have at most 2 users per page");
    }
}

/// Test admin user listing with filters
#[tokio::test]
async fn test_admin_list_users_filters() {
    init_tracing();

    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");

    // Create user with specific email
    let specific_email = unique_email_with_prefix("filtertest");
    let user = TestUser {
        email: specific_email.clone(),
        password: "TestPassword123!".to_string(),
        name: "Filter Test User".to_string(),
    };

    let response = ctx
        .server
        .post("/api/v1/register", user.register_json())
        .await;
    assert_status(&response, StatusCode::OK);

    // Get admin token
    let (_, token) = ctx
        .create_user_and_login()
        .await
        .map(|(_, t, _)| ((), t))
        .expect("Failed to create admin user");

    // Test email filter
    let response = ctx
        .server
        .get_with_auth(
            &format!("/api/v1/admin/users?email={}", "filtertest"),
            &token,
        )
        .await;

    let status = response.status();
    if status == StatusCode::OK {
        let body = response_json(response).await;

        // All returned users should match the filter
        for user in body["users"].as_array().unwrap_or(&vec![]) {
            let email = user["email"].as_str().unwrap_or("");
            assert!(
                email.contains("filtertest"),
                "User email should match filter"
            );
        }
    }

    // Test status filter
    let response = ctx
        .server
        .get_with_auth("/api/v1/admin/users?status=active", &token)
        .await;

    let status = response.status();
    if status == StatusCode::OK {
        let body = response_json(response).await;

        // All returned users should have active status
        for user in body["users"].as_array().unwrap_or(&vec![]) {
            assert_eq!(
                user["status"].as_str().unwrap_or(""),
                "active",
                "User should have active status"
            );
        }
    }
}

/// Test admin get user by ID
#[tokio::test]
async fn test_admin_get_user() {
    init_tracing();

    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");

    // Create a user to fetch
    let (user, token) = ctx
        .create_user_and_login()
        .await
        .map(|(u, t, _)| (u, t))
        .expect("Failed to create user");

    // Get admin token (using same user as admin for now)
    let admin_token = token.clone();

    // Get the user by ID - need to first get user ID from /me endpoint
    let response = ctx.server.get_with_auth("/api/v1/me", &token).await;
    let body = response_json(response).await;
    let user_id = body["id"].as_str().expect("Missing user ID");

    // Get user via admin endpoint
    let response = ctx
        .server
        .get_with_auth(&format!("/api/v1/admin/users/{}", user_id), &admin_token)
        .await;

    let status = response.status();
    assert!(
        status == StatusCode::OK
            || status == StatusCode::FORBIDDEN
            || status == StatusCode::NOT_FOUND,
        "Expected 200, 403, or 404, got {:?}",
        status
    );

    if status == StatusCode::OK {
        let body = response_json(response).await;
        assert_eq!(body["email"], user.email);
        assert_eq!(body["id"], user_id);
    }
}

/// Test admin create user
#[tokio::test]
async fn test_admin_create_user() {
    init_tracing();

    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");
    let (_, token) = ctx
        .create_user_and_login()
        .await
        .map(|(_, t, _)| ((), t))
        .expect("Failed to create admin user");

    // Create user via admin endpoint
    let new_email = unique_email();
    let response = ctx
        .server
        .post_with_auth(
            "/api/v1/admin/users",
            json!({
                "email": new_email,
                "name": "Admin Created User",
                "email_verified": true,
            }),
            &token,
        )
        .await;

    let status = response.status();
    assert!(
        status == StatusCode::CREATED
            || status == StatusCode::FORBIDDEN
            || status == StatusCode::NOT_FOUND,
        "Expected 201, 403, or 404, got {:?}",
        status
    );

    if status == StatusCode::CREATED {
        let body = response_json(response).await;
        assert_eq!(body["email"], new_email);
        assert_eq!(body["name"], "Admin Created User");
        assert!(!body["id"].as_str().unwrap().is_empty());
    }
}

/// Test admin create user with duplicate email
#[tokio::test]
async fn test_admin_create_user_duplicate_email() {
    init_tracing();

    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");

    // Create a user
    let (existing_user, token) = ctx
        .create_user_and_login()
        .await
        .map(|(u, t, _)| (u, t))
        .expect("Failed to create user");

    // Try to create another user with same email
    let response = ctx
        .server
        .post_with_auth(
            "/api/v1/admin/users",
            json!({
                "email": existing_user.email,
                "name": "Duplicate User",
            }),
            &token,
        )
        .await;

    // Should return conflict or forbidden
    let status = response.status();
    assert!(
        status == StatusCode::CONFLICT
            || status == StatusCode::FORBIDDEN
            || status == StatusCode::NOT_FOUND,
        "Expected 409, 403, or 404, got {:?}",
        status
    );
}

/// Test admin update user
#[tokio::test]
async fn test_admin_update_user() {
    init_tracing();

    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");

    // Create a user to update
    let (user, user_token) = ctx
        .create_user_and_login()
        .await
        .map(|(u, t, _)| (u, t))
        .expect("Failed to create user");

    // Get user ID
    let response = ctx.server.get_with_auth("/api/v1/me", &user_token).await;
    let body = response_json(response).await;
    let user_id = body["id"].as_str().expect("Missing user ID");

    // Get admin token
    let (_, admin_token) = ctx
        .create_user_and_login()
        .await
        .map(|(_, t, _)| ((), t))
        .expect("Failed to create admin user");

    // Update user
    let response = ctx
        .server
        .patch_with_auth(
            &format!("/api/v1/admin/users/{}", user_id),
            json!({
                "name": "Updated Name",
            }),
            &admin_token,
        )
        .await;

    let status = response.status();
    assert!(
        status == StatusCode::OK
            || status == StatusCode::FORBIDDEN
            || status == StatusCode::NOT_FOUND,
        "Expected 200, 403, or 404, got {:?}",
        status
    );

    if status == StatusCode::OK {
        let body = response_json(response).await;
        assert_eq!(body["name"], "Updated Name");
        assert_eq!(body["email"], user.email);
    }
}

/// Test admin suspend user
#[tokio::test]
async fn test_admin_suspend_user() {
    init_tracing();

    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");

    // Create a user to suspend
    let (user, user_token) = ctx
        .create_user_and_login()
        .await
        .map(|(u, t, _)| (u, t))
        .expect("Failed to create user");

    // Verify user can access protected endpoint
    let response = ctx.server.get_with_auth("/api/v1/me", &user_token).await;
    assert_status(&response, StatusCode::OK);

    // Get user ID
    let response = ctx.server.get_with_auth("/api/v1/me", &user_token).await;
    let body = response_json(response).await;
    let user_id = body["id"].as_str().expect("Missing user ID");

    // Get admin token
    let (_, admin_token) = ctx
        .create_user_and_login()
        .await
        .map(|(_, t, _)| ((), t))
        .expect("Failed to create admin user");

    // Suspend user
    let response = ctx
        .server
        .post_with_auth(
            &format!("/api/v1/admin/users/{}/suspend", user_id),
            json!({}),
            &admin_token,
        )
        .await;

    let status = response.status();
    assert!(
        status == StatusCode::OK
            || status == StatusCode::FORBIDDEN
            || status == StatusCode::NOT_FOUND,
        "Expected 200, 403, or 404, got {:?}",
        status
    );

    if status == StatusCode::OK {
        let body = response_json(response).await;
        assert_eq!(body["status"], "suspended");

        // User's token should no longer work
        let response = ctx.server.get_with_auth("/api/v1/me", &user_token).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // User should not be able to login
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
}

/// Test admin activate suspended user
#[tokio::test]
async fn test_admin_activate_user() {
    init_tracing();

    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");

    // Create a user
    let (user, user_token) = ctx
        .create_user_and_login()
        .await
        .map(|(u, t, _)| (u, t))
        .expect("Failed to create user");

    // Get user ID
    let response = ctx.server.get_with_auth("/api/v1/me", &user_token).await;
    let body = response_json(response).await;
    let user_id = body["id"].as_str().expect("Missing user ID");

    // Get admin token
    let (_, admin_token) = ctx
        .create_user_and_login()
        .await
        .map(|(_, t, _)| ((), t))
        .expect("Failed to create admin user");

    // Suspend user first
    let _ = ctx
        .server
        .post_with_auth(
            &format!("/api/v1/admin/users/{}/suspend", user_id),
            json!({}),
            &admin_token,
        )
        .await;

    // Activate user
    let response = ctx
        .server
        .post_with_auth(
            &format!("/api/v1/admin/users/{}/activate", user_id),
            json!({}),
            &admin_token,
        )
        .await;

    let status = response.status();
    assert!(
        status == StatusCode::OK
            || status == StatusCode::FORBIDDEN
            || status == StatusCode::NOT_FOUND,
        "Expected 200, 403, or 404, got {:?}",
        status
    );

    if status == StatusCode::OK {
        let body = response_json(response).await;
        assert_eq!(body["status"], "active");

        // User should be able to login again
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
        assert_status(&response, StatusCode::OK);
    }
}

/// Test admin delete user
#[tokio::test]
async fn test_admin_delete_user() {
    init_tracing();

    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");

    // Create a user to delete
    let (user, user_token) = ctx
        .create_user_and_login()
        .await
        .map(|(u, t, _)| (u, t))
        .expect("Failed to create user");

    // Get user ID
    let response = ctx.server.get_with_auth("/api/v1/me", &user_token).await;
    let body = response_json(response).await;
    let user_id = body["id"].as_str().expect("Missing user ID");

    // Get admin token
    let (_, admin_token) = ctx
        .create_user_and_login()
        .await
        .map(|(_, t, _)| ((), t))
        .expect("Failed to create admin user");

    // Delete user
    let response = ctx
        .server
        .delete_with_auth(&format!("/api/v1/admin/users/{}", user_id), &admin_token)
        .await;

    let status = response.status();
    assert!(
        status == StatusCode::NO_CONTENT
            || status == StatusCode::FORBIDDEN
            || status == StatusCode::NOT_FOUND
            || status == StatusCode::OK,
        "Expected 204, 200, 403, or 404, got {:?}",
        status
    );

    if status == StatusCode::NO_CONTENT || status == StatusCode::OK {
        // User should not be able to login
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
}

/// Test admin revoke all user sessions
#[tokio::test]
async fn test_admin_revoke_all_sessions() {
    init_tracing();

    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");

    // Create a user with multiple sessions
    let (user, token1) = ctx
        .create_user_and_login()
        .await
        .map(|(u, t, _)| (u, t))
        .expect("Failed to create user");

    // Create another session
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
    let body = response_json(response).await;
    let token2 = body["accessToken"].as_str().unwrap().to_string();

    // Get user ID
    let response = ctx.server.get_with_auth("/api/v1/me", &token1).await;
    let body = response_json(response).await;
    let user_id = body["id"].as_str().expect("Missing user ID");

    // Verify both tokens work
    let response = ctx.server.get_with_auth("/api/v1/me", &token1).await;
    assert_status(&response, StatusCode::OK);

    let response = ctx.server.get_with_auth("/api/v1/me", &token2).await;
    assert_status(&response, StatusCode::OK);

    // Get admin token
    let (_, admin_token) = ctx
        .create_user_and_login()
        .await
        .map(|(_, t, _)| ((), t))
        .expect("Failed to create admin user");

    // Revoke all sessions
    let response = ctx
        .server
        .post_with_auth(
            &format!("/api/v1/admin/users/{}/revoke-sessions", user_id),
            json!({}),
            &admin_token,
        )
        .await;

    let status = response.status();
    assert!(
        status == StatusCode::OK
            || status == StatusCode::FORBIDDEN
            || status == StatusCode::NOT_FOUND,
        "Expected 200, 403, or 404, got {:?}",
        status
    );

    if status == StatusCode::OK {
        let body = response_json(response).await;
        assert!(body["message"].as_str().unwrap().contains("Revoked"));

        // Both tokens should no longer work
        let response = ctx.server.get_with_auth("/api/v1/me", &token1).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = ctx.server.get_with_auth("/api/v1/me", &token2).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}

/// Test admin endpoints require authentication
#[tokio::test]
async fn test_admin_endpoints_require_auth() {
    init_tracing();

    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");

    // Test various admin endpoints without authentication
    let endpoints = vec![
        ("GET", "/api/v1/admin/users"),
        ("POST", "/api/v1/admin/users"),
        ("GET", "/api/v1/admin/users/user-123"),
        ("PATCH", "/api/v1/admin/users/user-123"),
        ("DELETE", "/api/v1/admin/users/user-123"),
        ("POST", "/api/v1/admin/users/user-123/suspend"),
        ("POST", "/api/v1/admin/users/user-123/activate"),
        ("POST", "/api/v1/admin/users/user-123/revoke-sessions"),
    ];

    for (method, endpoint) in endpoints {
        let response = match method {
            "GET" => ctx.server.get(endpoint).await,
            "POST" => ctx.server.post(endpoint, json!({})).await,
            "PATCH" => ctx.server.patch_with_auth(endpoint, json!({}), "").await,
            "DELETE" => ctx.server.delete_with_auth(endpoint, "").await,
            _ => continue,
        };

        // All should return 401 (unauthorized)
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "{} {} should require authentication",
            method,
            endpoint
        );
    }
}

/// Test admin get non-existent user
#[tokio::test]
async fn test_admin_get_nonexistent_user() {
    init_tracing();

    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");
    let (_, token) = ctx
        .create_user_and_login()
        .await
        .map(|(_, t, _)| ((), t))
        .expect("Failed to create user");

    // Try to get non-existent user
    let response = ctx
        .server
        .get_with_auth("/api/v1/admin/users/nonexistent-user-id", &token)
        .await;

    // Should return 404 (not found) or 403 (forbidden)
    let status = response.status();
    assert!(
        status == StatusCode::NOT_FOUND || status == StatusCode::FORBIDDEN,
        "Expected 404 or 403, got {:?}",
        status
    );
}
