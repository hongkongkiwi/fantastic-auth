//! Real integration coverage for admin org settings, password policy, and keys routes.

mod common;

use axum::http::StatusCode;
use common::{assert_status, response_json, test_db_available, TestContext};
use serde_json::json;

#[tokio::test]
async fn test_admin_org_settings_get_and_update() {
    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new().await.expect("Failed to create test context");
    let (_, token, _) = ctx
        .create_admin_user_and_login()
        .await
        .expect("Failed to create admin user");

    let create_org = ctx
        .server
        .post_with_auth(
            "/api/v1/organizations",
            json!({
                "name": "Org Settings Org",
                "slug": "org-settings-org"
            }),
            &token,
        )
        .await;
    assert_status(&create_org, StatusCode::OK);
    let org = response_json(create_org).await;
    let org_id = org["id"].as_str().expect("Missing org id").to_string();

    let get_before = ctx
        .server
        .get_with_auth(
            &format!("/api/v1/admin/organizations/{}/settings", org_id),
            &token,
        )
        .await;
    assert_status(&get_before, StatusCode::OK);
    let before = response_json(get_before).await;
    assert!(before["auth"].is_object());
    assert!(before["security"].is_object());

    let put = ctx
        .server
        .put_with_auth(
            &format!("/api/v1/admin/organizations/{}/settings", org_id),
            json!({
                "auth": {"allowRegistration": false},
                "security": {"mfaRequired": true},
                "branding": {"theme": "ocean"},
                "email": {"from": "security@example.com"},
                "oauth": {"providers": ["google"]},
                "localization": {"locale": "en-US"},
                "webhook": {"enabled": true},
                "privacy": {"retentionDays": 90},
                "advanced": {"featureFlag": true}
            }),
            &token,
        )
        .await;
    assert_status(&put, StatusCode::OK);
    let updated = response_json(put).await;
    assert_eq!(updated["branding"]["theme"], "ocean");
    assert_eq!(updated["privacy"]["retentionDays"], 90);

    let get_after = ctx
        .server
        .get_with_auth(
            &format!("/api/v1/admin/organizations/{}/settings", org_id),
            &token,
        )
        .await;
    assert_status(&get_after, StatusCode::OK);
    let after = response_json(get_after).await;
    assert_eq!(after["branding"]["theme"], "ocean");
    assert_eq!(after["webhook"]["enabled"], true);
}

#[tokio::test]
async fn test_admin_password_policy_get_update_and_test() {
    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new().await.expect("Failed to create test context");
    let (_, token, _) = ctx
        .create_admin_user_and_login()
        .await
        .expect("Failed to create admin user");

    let get_policy = ctx
        .server
        .get_with_auth("/api/v1/admin/settings/password-policy", &token)
        .await;
    assert_status(&get_policy, StatusCode::OK);
    let policy = response_json(get_policy).await;
    assert!(policy["minLength"].is_number());
    assert!(policy["maxLength"].is_number());

    let update_policy = ctx
        .server
        .put_with_auth(
            "/api/v1/admin/settings/password-policy",
            json!({
                "minLength": 12,
                "maxLength": 64,
                "requireUppercase": true,
                "requireLowercase": true,
                "requireNumbers": true,
                "requireSpecial": false,
                "enforcementMode": "warn"
            }),
            &token,
        )
        .await;
    assert_status(&update_policy, StatusCode::OK);
    let updated = response_json(update_policy).await;
    assert_eq!(updated["minLength"], 12);
    assert_eq!(updated["enforcementMode"], "warn");

    let invalid_update = ctx
        .server
        .put_with_auth(
            "/api/v1/admin/settings/password-policy",
            json!({
                "minLength": 4
            }),
            &token,
        )
        .await;
    assert_status(&invalid_update, StatusCode::BAD_REQUEST);

    let test_password = ctx
        .server
        .post_with_auth(
            "/api/v1/admin/settings/password-policy/test",
            json!({
                "password": "WeakPass",
                "email": "user@example.com",
                "name": "Test User"
            }),
            &token,
        )
        .await;
    assert_status(&test_password, StatusCode::OK);
    let tested = response_json(test_password).await;
    assert!(tested["valid"].is_boolean());
    assert!(tested["errors"].is_array());
    assert!(tested["strengthScore"].is_number());
}

#[tokio::test]
async fn test_admin_keys_list_rotate_and_deactivate() {
    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new().await.expect("Failed to create test context");
    let (_, token, _) = ctx
        .create_admin_user_and_login()
        .await
        .expect("Failed to create admin user");

    let list_before = ctx.server.get_with_auth("/api/v1/admin/keys", &token).await;
    assert_status(&list_before, StatusCode::OK);
    let _before = response_json(list_before).await;

    let rotate = ctx
        .server
        .post_with_auth(
            "/api/v1/admin/keys",
            json!({"keyType": "jwt_signing"}),
            &token,
        )
        .await;
    assert_status(&rotate, StatusCode::OK);
    let rotated = response_json(rotate).await;
    let key_id = rotated["id"].as_str().expect("Missing key id").to_string();
    assert_eq!(rotated["keyType"], "jwt_signing");
    assert_eq!(rotated["isActive"], true);

    let list_after = ctx.server.get_with_auth("/api/v1/admin/keys", &token).await;
    assert_status(&list_after, StatusCode::OK);
    let after = response_json(list_after).await;
    assert!(after
        .as_array()
        .unwrap_or(&vec![])
        .iter()
        .any(|k| k["id"] == key_id));

    let deactivate = ctx
        .server
        .post_with_auth(
            &format!("/api/v1/admin/keys/{}/deactivate", key_id),
            json!({}),
            &token,
        )
        .await;
    assert_status(&deactivate, StatusCode::OK);
    let deactivated = response_json(deactivate).await;
    assert_eq!(deactivated["deactivated"], true);

    let bad_rotate = ctx
        .server
        .post_with_auth(
            "/api/v1/admin/keys",
            json!({"keyType": "not_a_real_type"}),
            &token,
        )
        .await;
    assert_status(&bad_rotate, StatusCode::BAD_REQUEST);
}
