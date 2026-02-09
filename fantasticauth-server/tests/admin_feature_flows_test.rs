//! Real integration coverage for admin billing, API keys, and organizations.

mod common;

use axum::http::StatusCode;
use common::{assert_status, response_json, test_db_available, TestContext};
use serde_json::json;

#[tokio::test]
async fn test_admin_billing_disabled_behavior() {
    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new().await.expect("Failed to create test context");
    let (_, token, _) = ctx
        .create_admin_user_and_login()
        .await
        .expect("Failed to create admin user");

    let plans = ctx
        .server
        .get_with_auth("/api/v1/admin/billing/plans", &token)
        .await;
    assert_status(&plans, StatusCode::OK);
    let plans_body = response_json(plans).await;
    assert_eq!(plans_body["billing_enabled"], false);
    assert!(plans_body["plans"].is_array());

    let status = ctx
        .server
        .get_with_auth("/api/v1/admin/billing/status", &token)
        .await;
    assert_status(&status, StatusCode::BAD_REQUEST);
    let status_body = response_json(status).await;
    assert_eq!(status_body["error"]["code"], "BAD_REQUEST");
}

#[tokio::test]
async fn test_admin_api_keys_crud_flow() {
    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new().await.expect("Failed to create test context");
    let (_, token, _) = ctx
        .create_admin_user_and_login()
        .await
        .expect("Failed to create admin user");

    let create = ctx
        .server
        .post_with_auth(
            "/api/v1/admin/api-keys",
            json!({
                "name": "CI Key",
                "description": "For integration tests",
                "scope": "read_only",
                "expires_in_days": 7,
                "rate_limit_per_minute": 120
            }),
            &token,
        )
        .await;
    assert_status(&create, StatusCode::CREATED);
    let created = response_json(create).await;
    let key_id = created["id"].as_str().expect("Missing key id").to_string();
    assert!(created["key"].as_str().unwrap_or_default().starts_with("vault_"));

    let list = ctx
        .server
        .get_with_auth("/api/v1/admin/api-keys", &token)
        .await;
    assert_status(&list, StatusCode::OK);
    let list_body = response_json(list).await;
    assert!(list_body["keys"].as_array().unwrap_or(&vec![]).iter().any(|k| k["id"] == key_id));

    let get = ctx
        .server
        .get_with_auth(&format!("/api/v1/admin/api-keys/{}", key_id), &token)
        .await;
    assert_status(&get, StatusCode::OK);
    let get_body = response_json(get).await;
    assert_eq!(get_body["name"], "CI Key");

    let update = ctx
        .server
        .put_with_auth(
            &format!("/api/v1/admin/api-keys/{}", key_id),
            json!({
                "name": "CI Key Updated",
                "description": "Updated description",
                "rate_limit_per_minute": 240
            }),
            &token,
        )
        .await;
    assert_status(&update, StatusCode::OK);
    let update_body = response_json(update).await;
    assert_eq!(update_body["name"], "CI Key Updated");
    assert_eq!(update_body["rate_limit_per_minute"], 240);

    let stats = ctx
        .server
        .get_with_auth(&format!("/api/v1/admin/api-keys/{}/stats", key_id), &token)
        .await;
    assert_status(&stats, StatusCode::OK);
    let stats_body = response_json(stats).await;
    assert_eq!(stats_body["total_requests"], 0);

    let revoke = ctx
        .server
        .put_with_auth(
            &format!("/api/v1/admin/api-keys/{}/revoke", key_id),
            json!({}),
            &token,
        )
        .await;
    assert_status(&revoke, StatusCode::OK);

    let after_revoke = ctx
        .server
        .get_with_auth(&format!("/api/v1/admin/api-keys/{}", key_id), &token)
        .await;
    assert_status(&after_revoke, StatusCode::OK);
    let after_revoke_body = response_json(after_revoke).await;
    assert_eq!(after_revoke_body["is_active"], false);
}

#[tokio::test]
async fn test_admin_organization_update_and_delete_flow() {
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
                "name": "Acme Org",
                "slug": "acme-org"
            }),
            &token,
        )
        .await;
    assert_status(&create_org, StatusCode::OK);
    let created_org = response_json(create_org).await;
    let org_id = created_org["id"].as_str().expect("Missing org id").to_string();

    let update = ctx
        .server
        .patch_with_auth(
            &format!("/api/v1/admin/organizations/{}", org_id),
            json!({
                "name": "Acme Org Updated",
                "description": "Org used for admin integration tests",
                "logoUrl": "https://example.com/logo.png",
                "website": "https://example.com",
                "maxMembers": 250,
                "ssoRequired": true,
                "status": "inactive"
            }),
            &token,
        )
        .await;
    assert_status(&update, StatusCode::OK);
    let updated = response_json(update).await;
    assert_eq!(updated["name"], "Acme Org Updated");
    assert_eq!(updated["description"], "Org used for admin integration tests");
    assert_eq!(updated["logoUrl"], "https://example.com/logo.png");
    assert_eq!(updated["website"], "https://example.com");
    assert_eq!(updated["maxMembers"], 250);
    assert_eq!(updated["ssoRequired"], true);
    assert_eq!(updated["status"], "inactive");

    let list = ctx
        .server
        .get_with_auth("/api/v1/admin/organizations?status=inactive", &token)
        .await;
    assert_status(&list, StatusCode::OK);
    let list_body = response_json(list).await;
    assert!(list_body["data"].as_array().unwrap_or(&vec![]).iter().any(|o| o["id"] == org_id));

    let delete = ctx
        .server
        .delete_with_auth(&format!("/api/v1/admin/organizations/{}", org_id), &token)
        .await;
    assert_status(&delete, StatusCode::OK);

    let get_deleted = ctx
        .server
        .get_with_auth(&format!("/api/v1/admin/organizations/{}", org_id), &token)
        .await;
    assert_status(&get_deleted, StatusCode::NOT_FOUND);
}
