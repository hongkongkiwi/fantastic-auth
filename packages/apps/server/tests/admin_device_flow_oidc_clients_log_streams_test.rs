//! Real integration coverage for admin device flow approvals, OIDC clients, and log streams.

mod common;

use axum::http::StatusCode;
use common::{assert_status, response_json, test_db_available, TestContext};
use serde_json::json;

#[tokio::test]
async fn test_admin_device_flow_approve_and_deny() {
    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new().await.expect("Failed to create test context");
    let (user, token, _) = ctx
        .create_admin_user_and_login()
        .await
        .expect("Failed to create admin user");

    let (user_id, tenant_id): (String, String) = sqlx::query_as(
        r#"SELECT id::text, tenant_id::text FROM users WHERE email = $1"#,
    )
    .bind(&user.email)
    .fetch_one(ctx.server.state.db.pool())
    .await
    .expect("Failed to fetch user and tenant IDs");

    let approve_user_code = format!("APR{:08}", rand::random::<u32>());
    let approve_device_code = format!("dev-approve-{:08}", rand::random::<u32>());

    sqlx::query(
        r#"INSERT INTO oauth_device_codes (tenant_id, device_code, user_code, client_id, expires_at, status, interval_seconds)
           VALUES ($1::uuid, $2, $3, $4, NOW() + interval '10 minutes', 'pending', 5)"#,
    )
    .bind(&tenant_id)
    .bind(&approve_device_code)
    .bind(&approve_user_code)
    .bind("test-client")
    .execute(ctx.server.state.db.pool())
    .await
    .expect("Failed to insert pending device code");

    let approve = ctx
        .server
        .post_with_auth(
            &format!("/api/v1/admin/device-codes/{}/approve", approve_user_code),
            json!({"userId": user_id}),
            &token,
        )
        .await;
    assert_status(&approve, StatusCode::OK);
    let approve_body = response_json(approve).await;
    assert_eq!(approve_body["approved"], true);

    let status_after_approve: String = sqlx::query_scalar(
        r#"SELECT status::text FROM oauth_device_codes WHERE tenant_id = $1::uuid AND user_code = $2"#,
    )
    .bind(&tenant_id)
    .bind(&approve_user_code)
    .fetch_one(ctx.server.state.db.pool())
    .await
    .expect("Failed to fetch approved status");
    assert_eq!(status_after_approve, "approved");

    let deny_user_code = format!("DEN{:08}", rand::random::<u32>());
    let deny_device_code = format!("dev-deny-{:08}", rand::random::<u32>());

    sqlx::query(
        r#"INSERT INTO oauth_device_codes (tenant_id, device_code, user_code, client_id, expires_at, status, interval_seconds)
           VALUES ($1::uuid, $2, $3, $4, NOW() + interval '10 minutes', 'pending', 5)"#,
    )
    .bind(&tenant_id)
    .bind(&deny_device_code)
    .bind(&deny_user_code)
    .bind("test-client")
    .execute(ctx.server.state.db.pool())
    .await
    .expect("Failed to insert second pending device code");

    let deny = ctx
        .server
        .post_with_auth(
            &format!("/api/v1/admin/device-codes/{}/deny", deny_user_code),
            json!({}),
            &token,
        )
        .await;
    assert_status(&deny, StatusCode::OK);
    let deny_body = response_json(deny).await;
    assert_eq!(deny_body["approved"], true);

    let status_after_deny: String = sqlx::query_scalar(
        r#"SELECT status::text FROM oauth_device_codes WHERE tenant_id = $1::uuid AND user_code = $2"#,
    )
    .bind(&tenant_id)
    .bind(&deny_user_code)
    .fetch_one(ctx.server.state.db.pool())
    .await
    .expect("Failed to fetch denied status");
    assert_eq!(status_after_deny, "denied");

    let missing = ctx
        .server
        .post_with_auth(
            "/api/v1/admin/device-codes/NOPE1234/deny",
            json!({}),
            &token,
        )
        .await;
    assert_status(&missing, StatusCode::OK);
    let missing_body = response_json(missing).await;
    assert_eq!(missing_body["approved"], false);
}

#[tokio::test]
async fn test_admin_oidc_clients_crud_flow() {
    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new().await.expect("Failed to create test context");
    let (_, token, _) = ctx
        .create_admin_user_and_login()
        .await
        .expect("Failed to create admin user");

    let client_id = format!("int-client-{}", rand::random::<u32>());

    let create = ctx
        .server
        .post_with_auth(
            "/api/v1/admin/oidc/clients",
            json!({
                "name": "Integration OIDC Client",
                "clientId": client_id,
                "clientType": "confidential",
                "redirectUris": ["https://example.com/callback"],
                "allowedScopes": ["openid", "profile", "email"],
                "pkceRequired": true
            }),
            &token,
        )
        .await;
    assert_status(&create, StatusCode::OK);
    let created = response_json(create).await;
    assert_eq!(created["clientId"], client_id);

    let list = ctx
        .server
        .get_with_auth("/api/v1/admin/oidc/clients", &token)
        .await;
    assert_status(&list, StatusCode::OK);
    let list_body = response_json(list).await;
    assert!(list_body
        .as_array()
        .unwrap_or(&vec![])
        .iter()
        .any(|c| c["clientId"] == client_id));

    let get = ctx
        .server
        .get_with_auth(&format!("/api/v1/admin/oidc/clients/{}", client_id), &token)
        .await;
    assert_status(&get, StatusCode::OK);
    let got = response_json(get).await;
    assert_eq!(got["clientId"], client_id);

    let update = ctx
        .server
        .patch_with_auth(
            &format!("/api/v1/admin/oidc/clients/{}", client_id),
            json!({
                "name": "Integration OIDC Client Updated",
                "redirectUris": ["https://example.com/new-callback"],
                "allowedScopes": ["openid", "profile"],
                "pkceRequired": false
            }),
            &token,
        )
        .await;
    assert_status(&update, StatusCode::OK);
    let updated = response_json(update).await;
    assert_eq!(updated["name"], "Integration OIDC Client Updated");
    assert_eq!(updated["pkceRequired"], false);

    let delete = ctx
        .server
        .delete_with_auth(&format!("/api/v1/admin/oidc/clients/{}", client_id), &token)
        .await;
    assert_status(&delete, StatusCode::OK);

    let get_deleted = ctx
        .server
        .get_with_auth(&format!("/api/v1/admin/oidc/clients/{}", client_id), &token)
        .await;
    assert_status(&get_deleted, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_admin_log_streams_crud_flow() {
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
            "/api/v1/admin/log-streams",
            json!({
                "name": "Audit HTTP Stream",
                "destinationType": "http",
                "config": {
                    "url": "https://example.com/hooks/audit"
                },
                "filter": {
                    "events": ["login.success"]
                },
                "status": "active"
            }),
            &token,
        )
        .await;
    assert_status(&create, StatusCode::OK);
    let created = response_json(create).await;
    let stream_id = created["id"]
        .as_str()
        .expect("Missing stream id")
        .to_string();
    assert_eq!(created["destinationType"], "http");

    let list = ctx
        .server
        .get_with_auth("/api/v1/admin/log-streams", &token)
        .await;
    assert_status(&list, StatusCode::OK);
    let list_body = response_json(list).await;
    assert!(list_body
        .as_array()
        .unwrap_or(&vec![])
        .iter()
        .any(|s| s["id"] == stream_id));

    let get = ctx
        .server
        .get_with_auth(&format!("/api/v1/admin/log-streams/{}", stream_id), &token)
        .await;
    assert_status(&get, StatusCode::OK);
    let got = response_json(get).await;
    assert_eq!(got["id"], stream_id);

    let update = ctx
        .server
        .patch_with_auth(
            &format!("/api/v1/admin/log-streams/{}", stream_id),
            json!({
                "name": "Audit HTTP Stream Updated",
                "status": "paused",
                "filter": {"events": ["login.success", "login.failed"]}
            }),
            &token,
        )
        .await;
    assert_status(&update, StatusCode::OK);
    let updated = response_json(update).await;
    assert_eq!(updated["name"], "Audit HTTP Stream Updated");
    assert_eq!(updated["status"], "paused");

    let delete = ctx
        .server
        .delete_with_auth(&format!("/api/v1/admin/log-streams/{}", stream_id), &token)
        .await;
    assert_status(&delete, StatusCode::OK);

    let get_deleted = ctx
        .server
        .get_with_auth(&format!("/api/v1/admin/log-streams/{}", stream_id), &token)
        .await;
    assert_status(&get_deleted, StatusCode::NOT_FOUND);
}
