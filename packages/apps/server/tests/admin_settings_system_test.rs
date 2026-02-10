//! Real integration coverage for admin settings and system routes.

mod common;

use axum::http::StatusCode;
use common::{assert_status, response_json, test_db_available, TestContext};
use serde_json::json;

#[tokio::test]
async fn test_admin_settings_root_and_legacy_mfa_endpoint_behavior() {
    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new().await.expect("Failed to create test context");
    let (_, token, _) = ctx
        .create_admin_user_and_login()
        .await
        .expect("Failed to create admin user");

    let get_settings = ctx
        .server
        .get_with_auth("/api/v1/admin/settings", &token)
        .await;
    assert_status(&get_settings, StatusCode::OK);
    let settings_before = response_json(get_settings).await;
    assert!(settings_before["settings"].is_object());

    let patch_settings = ctx
        .server
        .patch_with_auth(
            "/api/v1/admin/settings",
            json!({
                "settings": {
                    "auth": settings_before["settings"]["auth"],
                    "security": settings_before["settings"]["security"],
                    "org": settings_before["settings"]["org"],
                    "branding": settings_before["settings"]["branding"],
                    "email": settings_before["settings"]["email"],
                    "sms": settings_before["settings"]["sms"],
                    "oauth": settings_before["settings"]["oauth"],
                    "localization": settings_before["settings"]["localization"],
                    "webhook": settings_before["settings"]["webhook"],
                    "privacy": settings_before["settings"]["privacy"],
                    "advanced": settings_before["settings"]["advanced"]
                },
                "reason": "root-settings-update-test"
            }),
            &token,
        )
        .await;
    assert_status(&patch_settings, StatusCode::OK);

    let patch_mfa = ctx
        .server
        .patch_with_auth(
            "/api/v1/admin/settings/mfa",
            json!({
                "required": true,
                "allowedMethods": ["totp", "webauthn"]
            }),
            &token,
        )
        .await;
    assert_status(&patch_mfa, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_admin_settings_auth_update_history_and_public() {
    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new().await.expect("Failed to create test context");
    let (user, token, _) = ctx
        .create_admin_user_and_login()
        .await
        .expect("Failed to create admin user");

    let tenant_id: String = sqlx::query_scalar(
        r#"SELECT tenant_id::text FROM users WHERE email = $1"#,
    )
    .bind(&user.email)
    .fetch_one(ctx.server.state.db.pool())
    .await
    .expect("Failed to fetch tenant id");

    let get_auth = ctx
        .server
        .get_with_auth("/api/v1/admin/settings/auth", &token)
        .await;
    assert_status(&get_auth, StatusCode::OK);
    let auth_before = response_json(get_auth).await;
    assert_eq!(auth_before["category"], "auth");

    let mut auth_settings = auth_before["settings"].clone();
    let current = auth_settings["allow_registration"].as_bool().unwrap_or(true);
    auth_settings["allow_registration"] = json!(!current);

    let patch_auth = ctx
        .server
        .patch_with_auth(
            "/api/v1/admin/settings/auth?reason=integration-test",
            auth_settings,
            &token,
        )
        .await;
    assert_status(&patch_auth, StatusCode::OK);
    let auth_updated = response_json(patch_auth).await;
    assert_eq!(auth_updated["allow_registration"], json!(!current));

    let get_auth_after = ctx
        .server
        .get_with_auth("/api/v1/admin/settings/auth", &token)
        .await;
    assert_status(&get_auth_after, StatusCode::OK);
    let auth_after = response_json(get_auth_after).await;
    assert_eq!(auth_after["settings"]["allow_registration"], json!(!current));

    let history = ctx
        .server
        .get_with_auth("/api/v1/admin/settings/history?category=auth", &token)
        .await;
    assert_status(&history, StatusCode::OK);
    let history_body = response_json(history).await;
    assert!(history_body["total"].as_i64().unwrap_or(0) >= 1);
    assert!(history_body["changes"].is_array());

    let public = ctx
        .server
        .get_with_auth(&format!("/api/v1/admin/settings/public/{}", tenant_id), &token)
        .await;
    assert_status(&public, StatusCode::OK);
    let public_body = response_json(public).await;
    assert_eq!(public_body["tenant_id"], tenant_id);
    assert_eq!(public_body["auth"]["allow_registration"], json!(!current));
    assert!(public_body["branding"].is_object());
    assert!(public_body["localization"].is_object());
}

#[tokio::test]
async fn test_admin_settings_get_all_and_update_all() {
    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new().await.expect("Failed to create test context");
    let (_, token, _) = ctx
        .create_admin_user_and_login()
        .await
        .expect("Failed to create admin user");

    let get_all = ctx
        .server
        .get_with_auth("/api/v1/admin/settings", &token)
        .await;
    assert_status(&get_all, StatusCode::OK);
    let all_before = response_json(get_all).await;
    assert!(all_before["settings"].is_object());

    let mut settings = all_before["settings"].clone();
    let current = settings["auth"]["allow_registration"]
        .as_bool()
        .unwrap_or(true);
    settings["auth"]["allow_registration"] = json!(!current);

    let patch_all = ctx
        .server
        .patch_with_auth(
            "/api/v1/admin/settings",
            json!({
                "settings": settings,
                "reason": "update-all-test"
            }),
            &token,
        )
        .await;
    assert_status(&patch_all, StatusCode::OK);
    let updated = response_json(patch_all).await;
    assert_eq!(updated["auth"]["allow_registration"], json!(!current));
}

#[tokio::test]
async fn test_admin_system_health() {
    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new().await.expect("Failed to create test context");
    let (_, token, _) = ctx
        .create_admin_user_and_login()
        .await
        .expect("Failed to create admin user");

    let response = ctx
        .server
        .get_with_auth("/api/v1/admin/system/health", &token)
        .await;
    assert_status(&response, StatusCode::OK);
    let body = response_json(response).await;

    assert_eq!(body["status"], "healthy");
    assert!(body["version"].as_str().is_some());
    assert!(matches!(body["database"].as_str(), Some("healthy" | "unhealthy")));
}
