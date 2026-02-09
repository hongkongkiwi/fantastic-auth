//! Integration coverage for admin risk, security policies, and custom domains.

mod common;

use axum::http::StatusCode;
use common::{assert_status, response_json, test_db_available, TestContext};
use serde_json::json;

#[tokio::test]
async fn test_admin_risk_config_and_assessments_flow() {
    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new().await.expect("Failed to create test context");
    let (_, token, _) = ctx
        .create_admin_user_and_login()
        .await
        .expect("Failed to create admin user");

    let get_config = ctx
        .server
        .get_with_auth("/api/v1/admin/risk/config", &token)
        .await;
    assert_status(&get_config, StatusCode::OK);

    let update_config = ctx
        .server
        .put_with_auth(
            "/api/v1/admin/risk/config",
            json!({
                "enabled": true,
                "velocity_window_seconds": 600,
                "max_velocity_attempts": 7,
                "unusual_hours_start": 22,
                "unusual_hours_end": 6,
                "max_distance_km": 750.0,
                "min_time_between_locations": 1.5,
                "device_trust_days": 45,
                "thresholds": {
                    "low": 25,
                    "medium": 55,
                    "high": 75,
                    "critical": 90
                }
            }),
            &token,
        )
        .await;
    assert_status(&update_config, StatusCode::OK);
    let updated = response_json(update_config).await;
    assert_eq!(updated["velocity_window_seconds"], 600);
    assert_eq!(updated["max_velocity_attempts"], 7);

    let assessments = ctx
        .server
        .get_with_auth("/api/v1/admin/risk/assessments", &token)
        .await;
    assert_status(&assessments, StatusCode::OK);

    let analytics = ctx
        .server
        .get_with_auth("/api/v1/admin/risk/analytics?days=7", &token)
        .await;
    assert_status(&analytics, StatusCode::OK);
    let analytics_body = response_json(analytics).await;
    assert_eq!(analytics_body["days"], 7);
}

#[tokio::test]
async fn test_admin_security_policies_create_update_flow() {
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
            "/api/v1/admin/security/policies",
            json!({
                "name": "Require Step-Up For High Risk",
                "enabled": true,
                "conditions": {"risk_score_gte": 70},
                "actions": {"require_mfa": true, "notify_admin": true}
            }),
            &token,
        )
        .await;
    assert_status(&create, StatusCode::OK);
    let created = response_json(create).await;
    let policy_id = created["id"].as_str().expect("missing policy id").to_string();
    assert_eq!(created["name"], "Require Step-Up For High Risk");

    let update = ctx
        .server
        .patch_with_auth(
            &format!("/api/v1/admin/security/policies/{}", policy_id),
            json!({
                "name": "Require Step-Up For Medium Risk",
                "enabled": false,
                "conditions": {"risk_score_gte": 50},
                "actions": {"require_mfa": true, "notify_admin": false}
            }),
            &token,
        )
        .await;
    assert_status(&update, StatusCode::OK);
    let updated = response_json(update).await;
    assert_eq!(updated["name"], "Require Step-Up For Medium Risk");
    assert_eq!(updated["enabled"], false);
    assert_eq!(updated["conditions"]["risk_score_gte"], 50);
}

#[tokio::test]
async fn test_admin_custom_domains_crud_and_health_flow() {
    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new().await.expect("Failed to create test context");
    let (_, token, _) = ctx
        .create_admin_user_and_login()
        .await
        .expect("Failed to create admin user");

    let add = ctx
        .server
        .post_with_auth(
            "/api/v1/admin/domains",
            json!({
                "domain": "auth.example.com",
                "is_primary": true,
                "verification_method": "dns"
            }),
            &token,
        )
        .await;
    assert_status(&add, StatusCode::CREATED);

    let list = ctx
        .server
        .get_with_auth("/api/v1/admin/domains", &token)
        .await;
    assert_status(&list, StatusCode::OK);
    let list_body = response_json(list).await;
    let domain_item = list_body["domains"]
        .as_array()
        .unwrap_or(&vec![])
        .iter()
        .find(|d| d["domain"] == "auth.example.com")
        .cloned()
        .expect("domain not found in list");

    let domain_id = domain_item["id"].as_str().expect("missing domain id").to_string();

    let get = ctx
        .server
        .get_with_auth(&format!("/api/v1/admin/domains/{}", domain_id), &token)
        .await;
    assert_status(&get, StatusCode::OK);

    let verification_status = ctx
        .server
        .get_with_auth(
            &format!("/api/v1/admin/domains/{}/verification-status", domain_id),
            &token,
        )
        .await;
    assert_status(&verification_status, StatusCode::OK);

    let health = ctx
        .server
        .get_with_auth(&format!("/api/v1/admin/domains/{}/health", domain_id), &token)
        .await;
    assert_status(&health, StatusCode::OK);

    let remove = ctx
        .server
        .delete_with_auth(&format!("/api/v1/admin/domains/{}", domain_id), &token)
        .await;
    assert_status(&remove, StatusCode::OK);
}
