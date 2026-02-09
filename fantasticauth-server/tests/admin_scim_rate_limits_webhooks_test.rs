//! Integration coverage for admin SCIM, rate limits, and webhooks.

mod common;

use axum::http::StatusCode;
use common::{assert_status, response_json, test_db_available, TestContext};
use serde_json::json;

#[tokio::test]
async fn test_admin_scim_token_and_config_flow() {
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
            "/api/v1/admin/scim/tokens",
            json!({
                "name": "Okta Provisioning",
                "expires_in_days": 30
            }),
            &token,
        )
        .await;
    assert_status(&create, StatusCode::OK);
    let created = response_json(create).await;
    let token_id = created["id"].as_str().expect("missing token id").to_string();
    assert!(created["token"].as_str().unwrap_or_default().starts_with("scim_"));

    let list = ctx
        .server
        .get_with_auth("/api/v1/admin/scim/tokens", &token)
        .await;
    assert_status(&list, StatusCode::OK);
    let list_body = response_json(list).await;
    assert!(list_body["tokens"].as_array().unwrap_or(&vec![]).iter().any(|t| t["id"] == token_id));

    let config_get = ctx
        .server
        .get_with_auth("/api/v1/admin/scim/config", &token)
        .await;
    assert_status(&config_get, StatusCode::OK);

    let config_update = ctx
        .server
        .put_with_auth(
            "/api/v1/admin/scim/config",
            json!({
                "enabled": true,
                "baseUrl": "https://example.com/scim/v2",
                "userSchema": {
                    "customAttributes": [],
                    "requiredAttributes": ["userName", "emails"]
                },
                "groupSchema": {
                    "syncMembers": true
                },
                "mappings": {
                    "autoCreateUsers": true,
                    "autoDeactivateUsers": true,
                    "defaultRole": "member"
                }
            }),
            &token,
        )
        .await;
    assert_status(&config_update, StatusCode::OK);
    let config_update_body = response_json(config_update).await;
    assert_eq!(config_update_body["enabled"], true);

    let stats = ctx
        .server
        .get_with_auth("/api/v1/admin/scim/stats", &token)
        .await;
    assert_status(&stats, StatusCode::OK);

    let audit_logs = ctx
        .server
        .get_with_auth("/api/v1/admin/scim/audit-logs?limit=10&offset=0", &token)
        .await;
    assert_status(&audit_logs, StatusCode::OK);

    let revoke = ctx
        .server
        .post_with_auth(&format!("/api/v1/admin/scim/tokens/{}", token_id), json!({}), &token)
        .await;
    assert_status(&revoke, StatusCode::OK);

    let delete = ctx
        .server
        .delete_with_auth(&format!("/api/v1/admin/scim/tokens/{}", token_id), &token)
        .await;
    assert_status(&delete, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn test_admin_rate_limits_config_and_blocked_ips_flow() {
    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new().await.expect("Failed to create test context");
    let (_, token, _) = ctx
        .create_admin_user_and_login()
        .await
        .expect("Failed to create admin user");

    let get_initial = ctx
        .server
        .get_with_auth("/api/v1/admin/rate-limits", &token)
        .await;
    assert_status(&get_initial, StatusCode::OK);

    let update = ctx
        .server
        .put_with_auth(
            "/api/v1/admin/rate-limits/config",
            json!({
                "api_per_minute": 250,
                "auth_per_minute": 25,
                "window_seconds": 60,
                "burst_allowance": 30,
                "auto_block_enabled": true,
                "auto_block_threshold": 8,
                "auto_block_duration_minutes": 120
            }),
            &token,
        )
        .await;
    assert_status(&update, StatusCode::OK);
    let updated_body = response_json(update).await;
    assert_eq!(updated_body["api_per_minute"], 250);
    assert_eq!(updated_body["auth_per_minute"], 25);

    let block = ctx
        .server
        .post_with_auth(
            "/api/v1/admin/rate-limits/block-ip",
            json!({
                "ip_address": "203.0.113.25",
                "duration_minutes": 45,
                "reason": "Excessive auth attempts"
            }),
            &token,
        )
        .await;
    assert_status(&block, StatusCode::OK);

    let blocked = ctx
        .server
        .get_with_auth("/api/v1/admin/rate-limits/blocked-ips", &token)
        .await;
    assert_status(&blocked, StatusCode::OK);
    let blocked_body = response_json(blocked).await;
    assert!(blocked_body
        .as_array()
        .unwrap_or(&vec![])
        .iter()
        .any(|e| e["ip_address"] == "203.0.113.25"));

    let metrics = ctx
        .server
        .get_with_auth("/api/v1/admin/rate-limits/metrics", &token)
        .await;
    assert_status(&metrics, StatusCode::OK);

    let unblock = ctx
        .server
        .delete_with_auth("/api/v1/admin/rate-limits/block-ip/203.0.113.25", &token)
        .await;
    assert_status(&unblock, StatusCode::OK);
}

#[tokio::test]
async fn test_admin_webhooks_crud_and_secret_rotation_flow() {
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
            "/api/v1/admin/webhooks",
            json!({
                "name": "Primary Webhook",
                "url": "https://example.com/webhooks/fantasticauth",
                "events": ["user.created", "user.updated"],
                "description": "Main destination"
            }),
            &token,
        )
        .await;
    assert_status(&create, StatusCode::CREATED);
    let created = response_json(create).await;
    let webhook_id = created["id"].as_str().expect("missing webhook id").to_string();

    let list = ctx
        .server
        .get_with_auth("/api/v1/admin/webhooks", &token)
        .await;
    assert_status(&list, StatusCode::OK);
    let list_body = response_json(list).await;
    assert!(list_body["webhooks"].as_array().unwrap_or(&vec![]).iter().any(|w| w["id"] == webhook_id));

    let update = ctx
        .server
        .patch_with_auth(
            &format!("/api/v1/admin/webhooks/{}", webhook_id),
            json!({
                "name": "Primary Webhook v2",
                "url": "https://example.com/webhooks/v2",
                "events": ["user.created", "organization.created"],
                "active": true,
                "max_retries": 5
            }),
            &token,
        )
        .await;
    assert_status(&update, StatusCode::OK);
    let updated = response_json(update).await;
    assert_eq!(updated["name"], "Primary Webhook v2");

    let deliveries = ctx
        .server
        .get_with_auth(
            &format!("/api/v1/admin/webhooks/{}/deliveries", webhook_id),
            &token,
        )
        .await;
    assert_status(&deliveries, StatusCode::OK);

    let rotate = ctx
        .server
        .post_with_auth(
            &format!("/api/v1/admin/webhooks/{}/rotate-secret", webhook_id),
            json!({}),
            &token,
        )
        .await;
    assert_status(&rotate, StatusCode::OK);
    let rotate_body = response_json(rotate).await;
    assert_eq!(rotate_body["message"], "Secret rotated successfully");
    assert!(rotate_body["secret"].as_str().unwrap_or_default().len() >= 64);

    let delete = ctx
        .server
        .delete_with_auth(&format!("/api/v1/admin/webhooks/{}", webhook_id), &token)
        .await;
    assert_status(&delete, StatusCode::NO_CONTENT);

    let get_deleted = ctx
        .server
        .get_with_auth(&format!("/api/v1/admin/webhooks/{}", webhook_id), &token)
        .await;
    assert_status(&get_deleted, StatusCode::NOT_FOUND);
}
