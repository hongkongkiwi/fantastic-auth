//! Real integration coverage for admin dashboard, branding, applications, and roles routes.

mod common;

use axum::http::StatusCode;
use common::{assert_status, response_json, test_db_available, TestContext};
use serde_json::json;

#[tokio::test]
async fn test_admin_dashboard_and_branding_routes() {
    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new().await.expect("Failed to create test context");
    let (_, token, _) = ctx
        .create_admin_user_and_login()
        .await
        .expect("Failed to create admin user");

    let dashboard = ctx.server.get_with_auth("/api/v1/admin/", &token).await;
    assert_status(&dashboard, StatusCode::OK);
    let dashboard_body = response_json(dashboard).await;
    assert!(dashboard_body["stats"]["total_users"].is_number());
    assert!(dashboard_body["stats"]["active_users"].is_number());
    assert!(dashboard_body["stats"]["pending_users"].is_number());
    assert!(dashboard_body["stats"]["total_organizations"].is_number());

    let get_branding = ctx
        .server
        .get_with_auth("/api/v1/admin/branding", &token)
        .await;
    assert_status(&get_branding, StatusCode::OK);
    let get_branding_body = response_json(get_branding).await;
    assert!(get_branding_body.is_object());

    let update_branding = ctx
        .server
        .patch_with_auth(
            "/api/v1/admin/branding",
            json!({
                "logoUrl": "https://example.com/logo.svg",
                "productName": "Fantastic Auth",
                "supportEmail": "support@example.com",
                "primaryColor": "#112233"
            }),
            &token,
        )
        .await;
    assert_status(&update_branding, StatusCode::OK);
    let updated_branding = response_json(update_branding).await;
    assert_eq!(updated_branding["logoUrl"], "https://example.com/logo.svg");
    assert_eq!(updated_branding["productName"], "Fantastic Auth");

    let get_theme = ctx
        .server
        .get_with_auth("/api/v1/admin/themes", &token)
        .await;
    assert_status(&get_theme, StatusCode::OK);
    let theme = response_json(get_theme).await;
    assert!(theme["theme"].is_object());

    let update_theme = ctx
        .server
        .patch_with_auth(
            "/api/v1/admin/themes",
            json!({
                "theme": {
                    "mode": "dark",
                    "font": "system"
                }
            }),
            &token,
        )
        .await;
    assert_status(&update_theme, StatusCode::OK);
    let updated_theme = response_json(update_theme).await;
    assert_eq!(updated_theme["theme"]["mode"], "dark");
}

#[tokio::test]
async fn test_admin_applications_crud_flow() {
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
                "name": "Apps Org",
                "slug": "apps-org"
            }),
            &token,
        )
        .await;
    assert_status(&create_org, StatusCode::OK);
    let org = response_json(create_org).await;
    let org_id = org["id"].as_str().expect("Missing org id").to_string();

    let create_project = ctx
        .server
        .post_with_auth(
            "/api/v1/admin/projects",
            json!({
                "orgId": org_id,
                "name": "Core Project",
                "slug": "core-project",
                "description": "Project used for application tests"
            }),
            &token,
        )
        .await;
    assert_status(&create_project, StatusCode::OK);
    let project = response_json(create_project).await;
    let project_id = project["id"]
        .as_str()
        .expect("Missing project id")
        .to_string();

    let create_app = ctx
        .server
        .post_with_auth(
            &format!("/api/v1/admin/projects/{}/apps", project_id),
            json!({
                "name": "Web Client",
                "appType": "oidc",
                "orgId": org["id"],
                "settings": {
                    "redirectUris": ["https://example.com/callback"]
                }
            }),
            &token,
        )
        .await;
    assert_status(&create_app, StatusCode::OK);
    let app = response_json(create_app).await;
    let app_id = app["id"].as_str().expect("Missing app id").to_string();
    assert_eq!(app["name"], "Web Client");

    let list_apps = ctx
        .server
        .get_with_auth(&format!("/api/v1/admin/projects/{}/apps", project_id), &token)
        .await;
    assert_status(&list_apps, StatusCode::OK);
    let apps = response_json(list_apps).await;
    assert!(apps
        .as_array()
        .unwrap_or(&vec![])
        .iter()
        .any(|a| a["id"] == app_id));

    let get_app = ctx
        .server
        .get_with_auth(&format!("/api/v1/admin/apps/{}", app_id), &token)
        .await;
    assert_status(&get_app, StatusCode::OK);
    let got = response_json(get_app).await;
    assert_eq!(got["id"], app_id);

    let update_app = ctx
        .server
        .patch_with_auth(
            &format!("/api/v1/admin/apps/{}", app_id),
            json!({
                "name": "Web Client Updated",
                "settings": {
                    "redirectUris": ["https://example.com/new-callback"]
                }
            }),
            &token,
        )
        .await;
    assert_status(&update_app, StatusCode::OK);
    let updated = response_json(update_app).await;
    assert_eq!(updated["name"], "Web Client Updated");

    let delete_app = ctx
        .server
        .delete_with_auth(&format!("/api/v1/admin/apps/{}", app_id), &token)
        .await;
    assert_status(&delete_app, StatusCode::OK);
    let deleted = response_json(delete_app).await;
    assert_eq!(deleted["deleted"], true);

    let get_deleted = ctx
        .server
        .get_with_auth(&format!("/api/v1/admin/apps/{}", app_id), &token)
        .await;
    assert_status(&get_deleted, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_admin_organization_roles_crud_flow() {
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
                "name": "Roles Org",
                "slug": "roles-org"
            }),
            &token,
        )
        .await;
    assert_status(&create_org, StatusCode::OK);
    let org = response_json(create_org).await;
    let org_id = org["id"].as_str().expect("Missing org id").to_string();

    let create_role = ctx
        .server
        .post_with_auth(
            &format!("/api/v1/admin/organizations/{}/roles", org_id),
            json!({
                "name": "auditor",
                "permissions": ["read:users", "read:audit"]
            }),
            &token,
        )
        .await;
    assert_status(&create_role, StatusCode::OK);
    let role = response_json(create_role).await;
    let role_id = role["id"].as_str().expect("Missing role id").to_string();
    assert_eq!(role["name"], "auditor");

    let list_roles = ctx
        .server
        .get_with_auth(&format!("/api/v1/admin/organizations/{}/roles", org_id), &token)
        .await;
    assert_status(&list_roles, StatusCode::OK);
    let list_body = response_json(list_roles).await;
    assert!(list_body["data"]
        .as_array()
        .unwrap_or(&vec![])
        .iter()
        .any(|r| r["id"] == role_id));

    let update_role = ctx
        .server
        .patch_with_auth(
            &format!("/api/v1/admin/organizations/{}/roles/{}", org_id, role_id),
            json!({
                "name": "auditor_plus",
                "permissions": ["read:users", "read:audit", "read:org"]
            }),
            &token,
        )
        .await;
    assert_status(&update_role, StatusCode::OK);
    let updated = response_json(update_role).await;
    assert_eq!(updated["name"], "auditor_plus");

    let delete_role = ctx
        .server
        .delete_with_auth(
            &format!("/api/v1/admin/organizations/{}/roles/{}", org_id, role_id),
            &token,
        )
        .await;
    assert_status(&delete_role, StatusCode::OK);
}
