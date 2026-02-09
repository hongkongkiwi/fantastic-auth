//! Real integration coverage for remaining admin route modules.

mod common;

use std::net::SocketAddr;

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{Request, StatusCode},
};
use base64::Engine as _;
use common::{assert_status, response_json, test_db_available, TestContext, TestServer};
use serde_json::json;
use tower::util::ServiceExt;

fn assert_status_in(response: &axum::response::Response<Body>, allowed: &[StatusCode]) {
    let actual = response.status();
    assert!(
        allowed.contains(&actual),
        "Expected one of {:?}, got {:?}",
        allowed,
        actual
    );
}

async fn fetch_user_ids(ctx: &TestContext, email: &str) -> (String, String) {
    sqlx::query_as::<_, (String, String)>(r#"SELECT id::text, tenant_id::text FROM users WHERE email = $1"#)
        .bind(email)
        .fetch_one(ctx.server.state.db.pool())
        .await
        .expect("Failed to fetch user and tenant IDs")
}

async fn create_org(ctx: &TestContext, token: &str, name: &str, slug: &str) -> String {
    let create_org = ctx
        .server
        .post_with_auth(
            "/api/v1/organizations",
            json!({
                "name": name,
                "slug": slug
            }),
            token,
        )
        .await;
    assert_status(&create_org, StatusCode::OK);
    response_json(create_org).await["id"]
        .as_str()
        .expect("Missing org id")
        .to_string()
}

async fn auth_multipart(
    server: &TestServer,
    path: &str,
    token: &str,
    boundary: &str,
    body: String,
) -> axum::response::Response<Body> {
    let req = Request::builder()
        .method("POST")
        .uri(path)
        .header(
            "Content-Type",
            format!("multipart/form-data; boundary={}", boundary),
        )
        .header("Authorization", format!("Bearer {}", token))
        .body(Body::from(body))
        .expect("Failed to build multipart request");

    server.app.clone().oneshot(req).await.expect("Request failed")
}

#[tokio::test]
async fn test_admin_remaining_actions_analytics_audit_exports_email_templates_i18n_and_audit_logs() {
    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new().await.expect("Failed to create test context");
    let (_, token, _) = ctx
        .create_admin_user_and_login()
        .await
        .expect("Failed to create admin user");

    let code = base64::engine::general_purpose::STANDARD.encode("(module)");
    let create_action = ctx
        .server
        .post_with_auth(
            "/api/v1/admin/actions",
            json!({
                "name": "post_login_hook",
                "trigger": "post_login",
                "status": "enabled",
                "runtime": "wasm",
                "codeBase64": code,
                "timeoutMs": 1200
            }),
            &token,
        )
        .await;
    assert_status(&create_action, StatusCode::OK);
    let created_action = response_json(create_action).await;
    let action_id = created_action["id"]
        .as_str()
        .expect("Missing action id")
        .to_string();

    let list_actions = ctx.server.get_with_auth("/api/v1/admin/actions", &token).await;
    assert_status(&list_actions, StatusCode::OK);
    let list_actions_body = response_json(list_actions).await;
    assert!(list_actions_body
        .as_array()
        .unwrap_or(&vec![])
        .iter()
        .any(|a| a["id"] == action_id));

    let get_action = ctx
        .server
        .get_with_auth(&format!("/api/v1/admin/actions/{}", action_id), &token)
        .await;
    assert_status(&get_action, StatusCode::OK);

    let update_action = ctx
        .server
        .patch_with_auth(
            &format!("/api/v1/admin/actions/{}", action_id),
            json!({
                "name": "post_login_hook_v2",
                "status": "disabled",
                "timeoutMs": 1400
            }),
            &token,
        )
        .await;
    assert_status(&update_action, StatusCode::OK);

    let delete_action = ctx
        .server
        .delete_with_auth(&format!("/api/v1/admin/actions/{}", action_id), &token)
        .await;
    assert_status(&delete_action, StatusCode::OK);

    for endpoint in [
        "/api/v1/admin/analytics/dashboard",
        "/api/v1/admin/analytics/logins",
        "/api/v1/admin/analytics/users",
        "/api/v1/admin/analytics/mfa",
        "/api/v1/admin/analytics/devices",
        "/api/v1/admin/analytics/geography",
        "/api/v1/admin/analytics/security",
        "/api/v1/admin/analytics/sessions",
        "/api/v1/admin/analytics/realtime",
        "/api/v1/admin/analytics/export?format=json&metrics=logins,users",
        "/api/v1/admin/analytics/trends",
    ] {
        let response = ctx.server.get_with_auth(endpoint, &token).await;
        assert_status(&response, StatusCode::OK);
    }

    let list_exports = ctx
        .server
        .get_with_auth("/api/v1/admin/audit-logs/exports", &token)
        .await;
    assert_status(&list_exports, StatusCode::OK);

    let create_export = ctx
        .server
        .post_with_auth(
            "/api/v1/admin/audit-logs/exports",
            json!({
                "format": "json",
                "from": "2025-01-01T00:00:00Z",
                "to": "2025-01-31T23:59:59Z"
            }),
            &token,
        )
        .await;
    assert_status(&create_export, StatusCode::OK);

    let list_webhooks = ctx
        .server
        .get_with_auth("/api/v1/admin/audit-logs/webhooks", &token)
        .await;
    assert_status(&list_webhooks, StatusCode::OK);

    let create_webhook = ctx
        .server
        .post_with_auth(
            "/api/v1/admin/audit-logs/webhooks",
            json!({
                "url": "https://example.com/audit/webhook",
                "secret": "secret-value-1234"
            }),
            &token,
        )
        .await;
    assert_status(&create_webhook, StatusCode::OK);
    let webhook_id = response_json(create_webhook).await["id"]
        .as_str()
        .expect("Missing webhook id")
        .to_string();

    let delete_webhook = ctx
        .server
        .delete_with_auth(
            &format!("/api/v1/admin/audit-logs/webhooks/{}", webhook_id),
            &token,
        )
        .await;
    assert_status(&delete_webhook, StatusCode::OK);

    let get_audit_logs = ctx
        .server
        .get_with_auth("/api/v1/admin/audit-logs?page=1&per_page=10", &token)
        .await;
    assert_status(&get_audit_logs, StatusCode::OK);

    let list_templates = ctx
        .server
        .get_with_auth("/api/v1/admin/email-templates", &token)
        .await;
    assert_status(&list_templates, StatusCode::OK);

    let list_variables = ctx
        .server
        .get_with_auth("/api/v1/admin/email-templates/variables", &token)
        .await;
    assert_status(&list_variables, StatusCode::OK);

    let get_template = ctx
        .server
        .get_with_auth("/api/v1/admin/email-templates/welcome", &token)
        .await;
    assert_status(&get_template, StatusCode::OK);

    let update_template = ctx
        .server
        .put_with_auth(
            "/api/v1/admin/email-templates/welcome",
            json!({
                "subject": "Welcome, {{name}}",
                "html_body": "<p>Hello {{name}}</p>",
                "text_body": "Hello {{name}}"
            }),
            &token,
        )
        .await;
    assert_status(&update_template, StatusCode::OK);

    let preview_template = ctx
        .server
        .post_with_auth(
            "/api/v1/admin/email-templates/welcome/preview",
            json!({"variables": {"name": "Integration User"}}),
            &token,
        )
        .await;
    assert_status(&preview_template, StatusCode::OK);

    let send_test = ctx
        .server
        .post_with_auth(
            "/api/v1/admin/email-templates/welcome/send-test",
            json!({
                "to_email": "qa@example.com",
                "variables": {"name": "Integration User"}
            }),
            &token,
        )
        .await;
    assert_status(&send_test, StatusCode::OK);

    let reset_template = ctx
        .server
        .post_with_auth(
            "/api/v1/admin/email-templates/welcome/reset",
            json!({}),
            &token,
        )
        .await;
    assert_status(&reset_template, StatusCode::OK);

    for endpoint in [
        "/api/v1/admin/i18n/languages",
        "/api/v1/admin/i18n/translations/en",
        "/api/v1/admin/i18n/translations/search?query=welcome",
        "/api/v1/admin/i18n/translations/stats",
    ] {
        let response = ctx.server.get_with_auth(endpoint, &token).await;
        assert_status(&response, StatusCode::OK);
    }

    let update_translation = ctx
        .server
        .put_with_auth(
            "/api/v1/admin/i18n/translations",
            json!({
                "lang": "en",
                "key": "admin.welcome",
                "value": "Welcome Admin"
            }),
            &token,
        )
        .await;
    assert_status(&update_translation, StatusCode::OK);

    let export_translations = ctx
        .server
        .post_with_auth(
            "/api/v1/admin/i18n/translations/export?lang=en&format=json",
            json!({}),
            &token,
        )
        .await;
    assert_status(&export_translations, StatusCode::OK);

    let import_translations = ctx
        .server
        .post_with_auth(
            "/api/v1/admin/i18n/translations/import",
            json!({
                "lang": "en",
                "format": "json",
                "data": {
                    "admin.banner": "Banner"
                },
                "overwrite_existing": true
            }),
            &token,
        )
        .await;
    assert_status(&import_translations, StatusCode::OK);
}

#[tokio::test]
async fn test_admin_remaining_groups_domains_idp_projects_and_tenant_admins() {
    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new().await.expect("Failed to create test context");
    let (admin_user, token, _) = ctx
        .create_admin_user_and_login()
        .await
        .expect("Failed to create admin user");
    let (admin_id, _) = fetch_user_ids(&ctx, &admin_user.email).await;

    let org_id = create_org(&ctx, &token, "Coverage Org", "coverage-org").await;
    let grant_org_id = create_org(&ctx, &token, "Coverage Grant Org", "coverage-grant-org").await;

    let create_group = ctx
        .server
        .post_with_auth(
            &format!("/api/v1/admin/organizations/{}/groups", org_id),
            json!({"name": "engineering", "description": "Engineering team"}),
            &token,
        )
        .await;
    assert_status(&create_group, StatusCode::OK);
    let group_id = response_json(create_group).await["id"]
        .as_str()
        .expect("Missing group id")
        .to_string();

    let list_groups = ctx
        .server
        .get_with_auth(
            &format!("/api/v1/admin/organizations/{}/groups?page=1&perPage=10", org_id),
            &token,
        )
        .await;
    assert_status(&list_groups, StatusCode::OK);

    let update_group = ctx
        .server
        .patch_with_auth(
            &format!("/api/v1/admin/groups/{}", group_id),
            json!({"name": "engineering-core"}),
            &token,
        )
        .await;
    assert_status(&update_group, StatusCode::OK);

    let list_group_members = ctx
        .server
        .get_with_auth(&format!("/api/v1/admin/groups/{}/members", group_id), &token)
        .await;
    assert_status(&list_group_members, StatusCode::OK);

    let member = common::TestUser::new();
    let register_member = ctx.server.post("/api/v1/register", member.register_json()).await;
    assert_status(&register_member, StatusCode::OK);
    let (member_id, _) = fetch_user_ids(&ctx, &member.email).await;

    let add_member = ctx
        .server
        .post_with_auth(
            &format!("/api/v1/admin/groups/{}/members", group_id),
            json!({ "userId": member_id }),
            &token,
        )
        .await;
    assert_status(&add_member, StatusCode::OK);

    let remove_member = ctx
        .server
        .delete_with_auth(
            &format!("/api/v1/admin/groups/{}/members/{}", group_id, member_id),
            &token,
        )
        .await;
    assert_status(&remove_member, StatusCode::OK);

    let create_domain = ctx
        .server
        .post_with_auth(
            &format!("/api/v1/admin/organizations/{}/domains", org_id),
            json!({
                "domain": format!("cov-{}.example.com", rand::random::<u32>()),
                "autoEnrollEnabled": true,
                "defaultRole": "member"
            }),
            &token,
        )
        .await;
    assert_status(&create_domain, StatusCode::OK);
    let created_domain = response_json(create_domain).await;
    let domain_id = created_domain["id"]
        .as_str()
        .expect("Missing domain id")
        .to_string();

    let list_domains = ctx
        .server
        .get_with_auth(
            &format!("/api/v1/admin/organizations/{}/domains", org_id),
            &token,
        )
        .await;
    assert_status(&list_domains, StatusCode::OK);

    let update_domain = ctx
        .server
        .patch_with_auth(
            &format!("/api/v1/admin/organizations/{}/domains/{}", org_id, domain_id),
            json!({"autoEnrollEnabled": false, "defaultRole": "viewer"}),
            &token,
        )
        .await;
    assert_status(&update_domain, StatusCode::OK);

    for endpoint in [
        format!(
            "/api/v1/admin/organizations/{}/domains/{}/verify",
            org_id, domain_id
        ),
        format!(
            "/api/v1/admin/organizations/{}/domains/{}/verify-dns",
            org_id, domain_id
        ),
        format!(
            "/api/v1/admin/organizations/{}/domains/{}/verify-html",
            org_id, domain_id
        ),
        format!(
            "/api/v1/admin/organizations/{}/domains/{}/verify-file",
            org_id, domain_id
        ),
    ] {
        let response = ctx.server.post_with_auth(&endpoint, json!({}), &token).await;
        assert_status(&response, StatusCode::OK);
    }

    let create_idp_provider = ctx
        .server
        .post_with_auth(
            "/api/v1/admin/idp/providers",
            json!({
                "orgId": org_id,
                "name": "Org OIDC",
                "providerType": "oidc",
                "status": "active",
                "config": {"issuer": "https://idp.example.com"}
            }),
            &token,
        )
        .await;
    assert_status(&create_idp_provider, StatusCode::OK);
    let idp_provider_id = response_json(create_idp_provider).await["id"]
        .as_str()
        .expect("Missing idp provider id")
        .to_string();

    let list_idp_providers = ctx
        .server
        .get_with_auth(&format!("/api/v1/admin/idp/providers?orgId={}", org_id), &token)
        .await;
    assert_status(&list_idp_providers, StatusCode::OK);

    let update_idp_provider = ctx
        .server
        .patch_with_auth(
            &format!("/api/v1/admin/idp/providers/{}", idp_provider_id),
            json!({
                "name": "Org OIDC Updated",
                "status": "inactive"
            }),
            &token,
        )
        .await;
    assert_status(&update_idp_provider, StatusCode::OK);

    let create_idp_domain = ctx
        .server
        .post_with_auth(
            "/api/v1/admin/idp/domains",
            json!({
                "orgId": org_id,
                "providerId": idp_provider_id,
                "domain": format!("sso-{}.example.com", rand::random::<u32>())
            }),
            &token,
        )
        .await;
    assert_status(&create_idp_domain, StatusCode::OK);
    let idp_domain_id = response_json(create_idp_domain).await["id"]
        .as_str()
        .expect("Missing idp domain id")
        .to_string();

    let list_idp_domains = ctx
        .server
        .get_with_auth(&format!("/api/v1/admin/idp/domains?orgId={}", org_id), &token)
        .await;
    assert_status(&list_idp_domains, StatusCode::OK);

    let create_project = ctx
        .server
        .post_with_auth(
            "/api/v1/admin/projects",
            json!({
                "orgId": org_id,
                "name": "Coverage Project",
                "slug": format!("coverage-project-{}", rand::random::<u16>()),
                "description": "Project for route coverage"
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

    let list_projects = ctx
        .server
        .get_with_auth(
            &format!("/api/v1/admin/projects?orgId={}&page=1&perPage=10", org_id),
            &token,
        )
        .await;
    assert_status(&list_projects, StatusCode::OK);

    let get_project = ctx
        .server
        .get_with_auth(&format!("/api/v1/admin/projects/{}", project_id), &token)
        .await;
    assert_status(&get_project, StatusCode::OK);

    let update_project = ctx
        .server
        .patch_with_auth(
            &format!("/api/v1/admin/projects/{}", project_id),
            json!({"name": "Coverage Project Updated", "status": "active"}),
            &token,
        )
        .await;
    assert_status(&update_project, StatusCode::OK);

    let create_role = ctx
        .server
        .post_with_auth(
            &format!("/api/v1/admin/projects/{}/roles", project_id),
            json!({"name": "project_reader", "permissions": ["read:project"]}),
            &token,
        )
        .await;
    assert_status(&create_role, StatusCode::OK);
    let role_id = response_json(create_role).await["id"]
        .as_str()
        .expect("Missing project role id")
        .to_string();

    let list_roles = ctx
        .server
        .get_with_auth(&format!("/api/v1/admin/projects/{}/roles", project_id), &token)
        .await;
    assert_status(&list_roles, StatusCode::OK);

    let update_role = ctx
        .server
        .patch_with_auth(
            &format!("/api/v1/admin/projects/{}/roles/{}", project_id, role_id),
            json!({"name": "project_reader_v2"}),
            &token,
        )
        .await;
    assert_status(&update_role, StatusCode::OK);

    let assign_role = ctx
        .server
        .post_with_auth(
            &format!("/api/v1/admin/projects/{}/assignments", project_id),
            json!({
                "roleId": role_id,
                "userId": admin_id
            }),
            &token,
        )
        .await;
    assert_status(&assign_role, StatusCode::OK);
    let assignment_id = response_json(assign_role).await["id"]
        .as_str()
        .expect("Missing assignment id")
        .to_string();

    let list_assignments = ctx
        .server
        .get_with_auth(
            &format!("/api/v1/admin/projects/{}/assignments", project_id),
            &token,
        )
        .await;
    assert_status(&list_assignments, StatusCode::OK);

    let create_grant = ctx
        .server
        .post_with_auth(
            &format!("/api/v1/admin/projects/{}/grants", project_id),
            json!({
                "grantedOrgId": grant_org_id,
                "defaultRoleId": role_id
            }),
            &token,
        )
        .await;
    assert_status(&create_grant, StatusCode::OK);
    let grant_id = response_json(create_grant).await["id"]
        .as_str()
        .expect("Missing grant id")
        .to_string();

    let list_grants = ctx
        .server
        .get_with_auth(&format!("/api/v1/admin/projects/{}/grants", project_id), &token)
        .await;
    assert_status(&list_grants, StatusCode::OK);

    let remove_assignment = ctx
        .server
        .delete_with_auth(
            &format!(
                "/api/v1/admin/projects/{}/assignments/{}",
                project_id, assignment_id
            ),
            &token,
        )
        .await;
    assert_status(&remove_assignment, StatusCode::OK);

    let delete_grant = ctx
        .server
        .delete_with_auth(
            &format!("/api/v1/admin/projects/{}/grants/{}", project_id, grant_id),
            &token,
        )
        .await;
    assert_status(&delete_grant, StatusCode::OK);

    let delete_role = ctx
        .server
        .delete_with_auth(
            &format!("/api/v1/admin/projects/{}/roles/{}", project_id, role_id),
            &token,
        )
        .await;
    assert_status(&delete_role, StatusCode::OK);

    let create_tenant_admin = ctx
        .server
        .post_with_auth(
            "/api/v1/admin/tenant-admins",
            json!({"userId": member_id, "role": "admin"}),
            &token,
        )
        .await;
    assert_status(&create_tenant_admin, StatusCode::OK);

    let list_tenant_admins = ctx
        .server
        .get_with_auth("/api/v1/admin/tenant-admins", &token)
        .await;
    assert_status(&list_tenant_admins, StatusCode::OK);

    let update_tenant_admin = ctx
        .server
        .patch_with_auth(
            &format!("/api/v1/admin/tenant-admins/{}", member_id),
            json!({"role": "owner", "status": "active"}),
            &token,
        )
        .await;
    assert_status(&update_tenant_admin, StatusCode::OK);

    let list_invites = ctx
        .server
        .get_with_auth("/api/v1/admin/tenant-admins/invitations", &token)
        .await;
    assert_status(&list_invites, StatusCode::OK);

    let create_invite = ctx
        .server
        .post_with_auth(
            "/api/v1/admin/tenant-admins/invitations",
            json!({"email": format!("invite-{}@example.com", rand::random::<u32>()), "role": "admin"}),
            &token,
        )
        .await;
    assert_status(&create_invite, StatusCode::OK);

    let remove_tenant_admin = ctx
        .server
        .delete_with_auth(&format!("/api/v1/admin/tenant-admins/{}", member_id), &token)
        .await;
    assert_status(&remove_tenant_admin, StatusCode::OK);

    let delete_idp_domain = ctx
        .server
        .delete_with_auth(&format!("/api/v1/admin/idp/domains/{}", idp_domain_id), &token)
        .await;
    assert_status(&delete_idp_domain, StatusCode::OK);

    let delete_idp_provider = ctx
        .server
        .delete_with_auth(
            &format!("/api/v1/admin/idp/providers/{}", idp_provider_id),
            &token,
        )
        .await;
    assert_status(&delete_idp_provider, StatusCode::OK);

    let delete_domain = ctx
        .server
        .delete_with_auth(
            &format!("/api/v1/admin/organizations/{}/domains/{}", org_id, domain_id),
            &token,
        )
        .await;
    assert_status(&delete_domain, StatusCode::OK);

    let delete_group = ctx
        .server
        .delete_with_auth(&format!("/api/v1/admin/groups/{}", group_id), &token)
        .await;
    assert_status(&delete_group, StatusCode::OK);

    let delete_project = ctx
        .server
        .delete_with_auth(&format!("/api/v1/admin/projects/{}", project_id), &token)
        .await;
    assert_status(&delete_project, StatusCode::OK);
}

#[tokio::test]
async fn test_admin_remaining_federation_impersonation_m2m_oidc_and_push_mfa() {
    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new().await.expect("Failed to create test context");
    let (admin_user, token, _) = ctx
        .create_admin_user_and_login()
        .await
        .expect("Failed to create admin user");
    let (admin_id, _) = fetch_user_ids(&ctx, &admin_user.email).await;

    let create_provider = ctx
        .server
        .post_with_auth(
            "/api/v1/admin/providers",
            json!({
                "name": "Federation OIDC",
                "type": "oidc",
                "config": {
                    "issuer": "https://accounts.example.com",
                    "authorizationEndpoint": "https://accounts.example.com/auth",
                    "tokenEndpoint": "https://accounts.example.com/token",
                    "userinfoEndpoint": "https://accounts.example.com/userinfo",
                    "jwksUri": "https://accounts.example.com/jwks.json",
                    "clientId": "fed-client-id",
                    "clientSecret": "fed-client-secret",
                    "scopes": ["openid", "email", "profile"]
                },
                "enabled": true,
                "priority": 10
            }),
            &token,
        )
        .await;
    assert_status(&create_provider, StatusCode::OK);
    let provider_id = response_json(create_provider).await["id"]
        .as_str()
        .expect("Missing provider id")
        .to_string();

    for endpoint in [
        "/api/v1/admin/providers".to_string(),
        format!("/api/v1/admin/providers/{}", provider_id),
    ] {
        let response = ctx.server.get_with_auth(&endpoint, &token).await;
        assert_status(&response, StatusCode::OK);
    }

    let update_provider = ctx
        .server
        .put_with_auth(
            &format!("/api/v1/admin/providers/{}", provider_id),
            json!({"name": "Federation OIDC Updated", "priority": 20}),
            &token,
        )
        .await;
    assert_status(&update_provider, StatusCode::OK);

    let create_realm = ctx
        .server
        .post_with_auth(
            "/api/v1/admin/realms",
            json!({
                "domain": format!("realm-{}.example.com", rand::random::<u32>()),
                "providerId": provider_id,
                "isDefault": false
            }),
            &token,
        )
        .await;
    assert_status(&create_realm, StatusCode::OK);
    let realm_id = response_json(create_realm).await["id"]
        .as_str()
        .expect("Missing realm id")
        .to_string();

    let list_realms = ctx.server.get_with_auth("/api/v1/admin/realms", &token).await;
    assert_status(&list_realms, StatusCode::OK);

    let create_trust = ctx
        .server
        .post_with_auth(
            "/api/v1/admin/trusts",
            json!({
                "providerId": provider_id,
                "metadataXml": "<xml>metadata</xml>",
                "certificateFingerprint": "aa:bb:cc:dd",
                "trustLevel": "standard",
                "autoProvisionUsers": true,
                "allowedClaims": ["email", "name"]
            }),
            &token,
        )
        .await;
    assert_status(&create_trust, StatusCode::OK);
    let trust_id = response_json(create_trust).await["id"]
        .as_str()
        .expect("Missing trust id")
        .to_string();

    for endpoint in [
        "/api/v1/admin/trusts".to_string(),
        format!("/api/v1/admin/trusts/{}", trust_id),
    ] {
        let response = ctx.server.get_with_auth(&endpoint, &token).await;
        assert_status(&response, StatusCode::OK);
    }

    let update_trust = ctx
        .server
        .put_with_auth(
            &format!("/api/v1/admin/trusts/{}", trust_id),
            json!({"trustLevel": "high", "autoProvisionUsers": false}),
            &token,
        )
        .await;
    assert_status(&update_trust, StatusCode::OK);

    let refresh_trust = ctx
        .server
        .post_with_auth(
            &format!("/api/v1/admin/trusts/{}/refresh", trust_id),
            json!({}),
            &token,
        )
        .await;
    assert_status_in(&refresh_trust, &[StatusCode::OK, StatusCode::BAD_REQUEST]);

    let discover_provider = ctx
        .server
        .post_with_auth(
            "/api/v1/admin/discover",
            json!({"email": "user@example.com"}),
            &token,
        )
        .await;
    assert_status(&discover_provider, StatusCode::OK);

    let create_m2m = ctx
        .server
        .post_with_auth(
            "/api/v1/admin/service-accounts",
            json!({
                "name": "integration-service",
                "description": "service account for coverage",
                "scopes": ["api:read"],
                "permissions": ["read:data"]
            }),
            &token,
        )
        .await;
    assert_status(&create_m2m, StatusCode::CREATED);
    let m2m = response_json(create_m2m).await;
    let service_account_id = m2m["id"]
        .as_str()
        .expect("Missing service account id")
        .to_string();

    let list_service_accounts = ctx
        .server
        .get_with_auth("/api/v1/admin/service-accounts?page=1&per_page=10", &token)
        .await;
    assert_status(&list_service_accounts, StatusCode::OK);

    let get_service_account = ctx
        .server
        .get_with_auth(
            &format!("/api/v1/admin/service-accounts/{}", service_account_id),
            &token,
        )
        .await;
    assert_status(&get_service_account, StatusCode::OK);

    let update_service_account = ctx
        .server
        .put_with_auth(
            &format!("/api/v1/admin/service-accounts/{}", service_account_id),
            json!({"name": "integration-service-updated"}),
            &token,
        )
        .await;
    assert_status(&update_service_account, StatusCode::OK);

    let rotate_secret = ctx
        .server
        .post_with_auth(
            &format!("/api/v1/admin/service-accounts/{}/rotate-secret", service_account_id),
            json!({}),
            &token,
        )
        .await;
    assert_status(&rotate_secret, StatusCode::OK);

    let create_api_key = ctx
        .server
        .post_with_auth(
            &format!("/api/v1/admin/service-accounts/{}/keys", service_account_id),
            json!({"name": "primary-key", "expires_in_days": 7}),
            &token,
        )
        .await;
    assert_status(&create_api_key, StatusCode::CREATED);
    let key_id = response_json(create_api_key).await["id"]
        .as_str()
        .expect("Missing api key id")
        .to_string();

    let list_keys = ctx
        .server
        .get_with_auth(
            &format!("/api/v1/admin/service-accounts/{}/keys", service_account_id),
            &token,
        )
        .await;
    assert_status(&list_keys, StatusCode::OK);

    let revoke_key = ctx
        .server
        .delete_with_auth(
            &format!(
                "/api/v1/admin/service-accounts/{}/keys/{}",
                service_account_id, key_id
            ),
            &token,
        )
        .await;
    assert_status(&revoke_key, StatusCode::NO_CONTENT);

    let revoke_all = ctx
        .server
        .post_with_auth(
            &format!("/api/v1/admin/service-accounts/{}/revoke-keys", service_account_id),
            json!({}),
            &token,
        )
        .await;
    assert_status(&revoke_all, StatusCode::OK);

    let create_oidc = ctx
        .server
        .post_with_auth(
            "/api/v1/admin/oidc/clients",
            json!({
                "name": "OIDC Advanced",
                "clientId": format!("adv-client-{}", rand::random::<u32>()),
                "clientType": "confidential",
                "redirectUris": ["https://example.com/callback"],
                "allowedScopes": ["openid", "profile", "email"]
            }),
            &token,
        )
        .await;
    assert_status(&create_oidc, StatusCode::OK);
    let oidc_client_id = response_json(create_oidc).await["clientId"]
        .as_str()
        .expect("Missing oidc client id")
        .to_string();

    let rotate_client_secret = ctx
        .server
        .post_with_auth(
            &format!(
                "/api/v1/admin/oidc/clients/{}/rotate-secret",
                oidc_client_id
            ),
            json!({}),
            &token,
        )
        .await;
    assert_status(&rotate_client_secret, StatusCode::OK);

    let get_client_usage = ctx
        .server
        .get_with_auth(
            &format!("/api/v1/admin/oidc/clients/{}/usage", oidc_client_id),
            &token,
        )
        .await;
    assert_status(&get_client_usage, StatusCode::OK);

    let list_scopes = ctx
        .server
        .get_with_auth("/api/v1/admin/oidc/scopes", &token)
        .await;
    assert_status(&list_scopes, StatusCode::OK);

    let delete_oidc = ctx
        .server
        .delete_with_auth(
            &format!("/api/v1/admin/oidc/clients/{}", oidc_client_id),
            &token,
        )
        .await;
    assert_status(&delete_oidc, StatusCode::OK);

    let start_impersonation_body = json!({
        "reason": "debugging tenant issue",
        "duration_minutes": 10
    });
    let mut impersonation_req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/admin/users/{}/impersonate", admin_id))
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", token))
        .body(Body::from(start_impersonation_body.to_string()))
        .expect("Failed to build impersonation request");
    impersonation_req
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 9000))));
    let start_impersonation = ctx
        .server
        .app
        .clone()
        .oneshot(impersonation_req)
        .await
        .expect("Impersonation request failed");
    assert_status(&start_impersonation, StatusCode::FORBIDDEN);

    let list_impersonations = ctx
        .server
        .get_with_auth("/api/v1/admin/impersonations?page=1&per_page=20", &token)
        .await;
    assert_status(&list_impersonations, StatusCode::OK);

    let end_impersonation = ctx
        .server
        .delete_with_auth("/api/v1/admin/impersonation", &token)
        .await;
    assert_status_in(&end_impersonation, &[StatusCode::BAD_REQUEST, StatusCode::OK]);

    for (path, method, body, allowed) in [
        (
            "/api/v1/admin/push-mfa/settings".to_string(),
            "GET",
            json!({}),
            vec![StatusCode::OK],
        ),
        (
            "/api/v1/admin/push-mfa/settings".to_string(),
            "PUT",
            json!({"requestTimeoutSeconds": 45, "maxDevicesPerUser": 5}),
            vec![StatusCode::OK],
        ),
        (
            "/api/v1/admin/push-mfa/settings/test".to_string(),
            "POST",
            json!({}),
            vec![StatusCode::OK, StatusCode::BAD_REQUEST],
        ),
        (
            "/api/v1/admin/push-mfa/stats".to_string(),
            "GET",
            json!({}),
            vec![StatusCode::OK],
        ),
        (
            "/api/v1/admin/push-mfa/stats/overview".to_string(),
            "GET",
            json!({}),
            vec![StatusCode::OK],
        ),
        (
            "/api/v1/admin/push-mfa/requests?page=1&perPage=10".to_string(),
            "GET",
            json!({}),
            vec![StatusCode::OK],
        ),
    ] {
        let response = match method {
            "GET" => ctx.server.get_with_auth(&path, &token).await,
            "POST" => ctx.server.post_with_auth(&path, body, &token).await,
            "PUT" => ctx.server.put_with_auth(&path, body, &token).await,
            _ => unreachable!("unexpected method"),
        };
        assert_status_in(&response, &allowed);
    }

    let delete_service_account = ctx
        .server
        .delete_with_auth(
            &format!("/api/v1/admin/service-accounts/{}", service_account_id),
            &token,
        )
        .await;
    assert_status(&delete_service_account, StatusCode::NO_CONTENT);

    let delete_trust = ctx
        .server
        .delete_with_auth(&format!("/api/v1/admin/trusts/{}", trust_id), &token)
        .await;
    assert_status(&delete_trust, StatusCode::OK);

    let delete_realm = ctx
        .server
        .delete_with_auth(&format!("/api/v1/admin/realms/{}", realm_id), &token)
        .await;
    assert_status(&delete_realm, StatusCode::OK);

    let delete_provider = ctx
        .server
        .delete_with_auth(&format!("/api/v1/admin/providers/{}", provider_id), &token)
        .await;
    assert_status(&delete_provider, StatusCode::OK);
}

#[tokio::test]
async fn test_admin_remaining_directory_bulk_and_migrations() {
    if !test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }

    let ctx = TestContext::new().await.expect("Failed to create test context");
    let (_, token, _) = ctx
        .create_admin_user_and_login()
        .await
        .expect("Failed to create admin user");

    let create_connection = ctx
        .server
        .post_with_auth(
            "/api/v1/admin/directory/ldap",
            json!({
                "name": format!("LDAP Coverage {}", rand::random::<u16>()),
                "url": "ldap://localhost:389",
                "bind_dn": "cn=admin,dc=example,dc=org",
                "bind_password": "secret",
                "base_dn": "dc=example,dc=org",
                "sync_interval_minutes": 60
            }),
            &token,
        )
        .await;
    assert_status(&create_connection, StatusCode::CREATED);
    let connection_id = response_json(create_connection).await["id"]
        .as_str()
        .expect("Missing ldap connection id")
        .to_string();

    for endpoint in [
        "/api/v1/admin/directory/ldap".to_string(),
        format!("/api/v1/admin/directory/ldap/{}", connection_id),
        format!("/api/v1/admin/directory/ldap/{}/sync/status", connection_id),
        format!("/api/v1/admin/directory/ldap/{}/logs?page=1&per_page=10", connection_id),
    ] {
        let response = ctx.server.get_with_auth(&endpoint, &token).await;
        assert_status(&response, StatusCode::OK);
    }

    let update_connection = ctx
        .server
        .put_with_auth(
            &format!("/api/v1/admin/directory/ldap/{}", connection_id),
            json!({"name": "LDAP Coverage Updated", "enabled": true}),
            &token,
        )
        .await;
    assert_status(&update_connection, StatusCode::OK);

    let test_connection = ctx
        .server
        .post_with_auth(
            &format!("/api/v1/admin/directory/ldap/{}/test", connection_id),
            json!({}),
            &token,
        )
        .await;
    assert_status(&test_connection, StatusCode::OK);

    let trigger_sync = ctx
        .server
        .post_with_auth(
            &format!("/api/v1/admin/directory/ldap/{}/sync", connection_id),
            json!({"sync_type": "full"}),
            &token,
        )
        .await;
    assert_status_in(&trigger_sync, &[StatusCode::OK, StatusCode::CONFLICT]);

    let log_id = response_json(
        ctx.server
            .get_with_auth(
                &format!("/api/v1/admin/directory/ldap/{}/logs", connection_id),
                &token,
            )
            .await,
    )
    .await["data"]
        .as_array()
        .and_then(|logs| logs.first())
        .and_then(|log| log["id"].as_str())
        .unwrap_or("00000000-0000-0000-0000-000000000000")
        .to_string();

    let get_sync_log = ctx
        .server
        .get_with_auth(&format!("/api/v1/admin/directory/ldap/logs/{}", log_id), &token)
        .await;
    assert_status_in(&get_sync_log, &[StatusCode::OK, StatusCode::NOT_FOUND]);

    let ldap_authenticate = ctx
        .server
        .post_with_auth(
            "/api/v1/admin/directory/ldap/authenticate",
            json!({"email": "user@example.com", "password": "bad-password"}),
            &token,
        )
        .await;
    assert_status_in(
        &ldap_authenticate,
        &[StatusCode::OK, StatusCode::INTERNAL_SERVER_ERROR],
    );

    let boundary = "----coverage-boundary";
    let bulk_csv =
        "email,name\nbulk.user@example.com,Bulk User\n".to_string();
    let bulk_body = format!(
        "--{b}\r\nContent-Disposition: form-data; name=\"format\"\r\n\r\ncsv\r\n--{b}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"users.csv\"\r\nContent-Type: text/csv\r\n\r\n{csv}\r\n--{b}--\r\n",
        b = boundary,
        csv = bulk_csv
    );

    let start_import = auth_multipart(
        &ctx.server,
        "/api/v1/admin/bulk/import",
        &token,
        boundary,
        bulk_body,
    )
    .await;
    assert_status(&start_import, StatusCode::OK);
    let import_job_id = response_json(start_import).await["jobId"]
        .as_str()
        .expect("Missing import job id")
        .to_string();

    let import_status = ctx
        .server
        .get_with_auth(&format!("/api/v1/admin/bulk/import/{}", import_job_id), &token)
        .await;
    assert_status(&import_status, StatusCode::OK);

    let import_download = ctx
        .server
        .get_with_auth(
            &format!("/api/v1/admin/bulk/import/{}/download", import_job_id),
            &token,
        )
        .await;
    assert_status_in(&import_download, &[StatusCode::OK, StatusCode::NOT_FOUND]);

    let template_csv = ctx
        .server
        .get_with_auth("/api/v1/admin/bulk/template/csv", &token)
        .await;
    assert_status(&template_csv, StatusCode::OK);

    let template_json = ctx
        .server
        .get_with_auth("/api/v1/admin/bulk/template/json", &token)
        .await;
    assert_status(&template_json, StatusCode::OK);

    let start_export = ctx
        .server
        .post_with_auth(
            "/api/v1/admin/bulk/export",
            json!({"format": "csv", "options": {}}),
            &token,
        )
        .await;
    assert_status(&start_export, StatusCode::OK);
    let export_job_id = response_json(start_export).await["jobId"]
        .as_str()
        .expect("Missing export job id")
        .to_string();

    let export_status = ctx
        .server
        .get_with_auth(&format!("/api/v1/admin/bulk/export/{}", export_job_id), &token)
        .await;
    assert_status(&export_status, StatusCode::OK);

    let export_download = ctx
        .server
        .get_with_auth(
            &format!("/api/v1/admin/bulk/export/{}/download", export_job_id),
            &token,
        )
        .await;
    assert_status_in(&export_download, &[StatusCode::OK, StatusCode::NOT_FOUND]);

    let list_bulk_jobs = ctx
        .server
        .get_with_auth("/api/v1/admin/bulk/jobs?limit=10", &token)
        .await;
    assert_status(&list_bulk_jobs, StatusCode::OK);

    let delete_bulk_job = ctx
        .server
        .delete_with_auth(&format!("/api/v1/admin/bulk/jobs/{}", export_job_id), &token)
        .await;
    assert_status_in(&delete_bulk_job, &[StatusCode::OK, StatusCode::NOT_FOUND]);

    let auth0_migration = ctx
        .server
        .post_with_auth(
            "/api/v1/admin/migrations/auth0",
            json!({
                "domain": "example.auth0.com",
                "client_id": "auth0-client",
                "client_secret": "auth0-secret",
                "dry_run": true
            }),
            &token,
        )
        .await;
    assert_status_in(&auth0_migration, &[StatusCode::OK, StatusCode::BAD_REQUEST]);

    let firebase_migration = ctx
        .server
        .post_with_auth(
            "/api/v1/admin/migrations/firebase",
            json!({
                "project_id": "firebase-project",
                "credentials_json": "{\"type\":\"service_account\",\"project_id\":\"x\",\"private_key_id\":\"x\",\"private_key\":\"-----BEGIN PRIVATE KEY-----\\nabc\\n-----END PRIVATE KEY-----\\n\",\"client_email\":\"x@example.com\",\"client_id\":\"x\",\"auth_uri\":\"https://accounts.google.com/o/oauth2/auth\",\"token_uri\":\"https://oauth2.googleapis.com/token\"}",
                "dry_run": true
            }),
            &token,
        )
        .await;
    assert_status_in(&firebase_migration, &[StatusCode::OK, StatusCode::BAD_REQUEST]);

    let cognito_migration = ctx
        .server
        .post_with_auth(
            "/api/v1/admin/migrations/cognito",
            json!({
                "region": "us-east-1",
                "user_pool_id": "us-east-1_pool",
                "access_key_id": "AKIA...",
                "secret_access_key": "secret",
                "dry_run": true
            }),
            &token,
        )
        .await;
    assert_status_in(&cognito_migration, &[StatusCode::OK, StatusCode::BAD_REQUEST]);

    let csv_boundary = "----migration-boundary";
    let migration_config = json!({"email_column": "email", "name_column": "name"}).to_string();
    let migration_csv = "email,name\nmigrated.user@example.com,Migrated User\n";
    let migration_body = format!(
        "--{b}\r\nContent-Disposition: form-data; name=\"config\"\r\n\r\n{config}\r\n--{b}\r\nContent-Disposition: form-data; name=\"dry_run\"\r\n\r\ntrue\r\n--{b}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"migration.csv\"\r\nContent-Type: text/csv\r\n\r\n{csv}\r\n--{b}--\r\n",
        b = csv_boundary,
        config = migration_config,
        csv = migration_csv
    );
    let csv_migration = auth_multipart(
        &ctx.server,
        "/api/v1/admin/migrations/csv",
        &token,
        csv_boundary,
        migration_body,
    )
    .await;
    assert_status_in(&csv_migration, &[StatusCode::OK, StatusCode::BAD_REQUEST]);
    let migration_id = response_json(csv_migration).await["id"]
        .as_str()
        .unwrap_or("00000000-0000-0000-0000-000000000000")
        .to_string();

    let validate_body = format!(
        "--{b}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"validate.csv\"\r\nContent-Type: text/csv\r\n\r\n{csv}\r\n--{b}--\r\n",
        b = csv_boundary,
        csv = migration_csv
    );
    let validate_csv = auth_multipart(
        &ctx.server,
        "/api/v1/admin/migrations/validate/csv",
        &token,
        csv_boundary,
        validate_body,
    )
    .await;
    assert_status(&validate_csv, StatusCode::OK);

    let preview_body = format!(
        "--{b}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"preview.csv\"\r\nContent-Type: text/csv\r\n\r\n{csv}\r\n--{b}--\r\n",
        b = csv_boundary,
        csv = migration_csv
    );
    let preview_csv = auth_multipart(
        &ctx.server,
        "/api/v1/admin/migrations/preview/csv",
        &token,
        csv_boundary,
        preview_body,
    )
    .await;
    assert_status(&preview_csv, StatusCode::OK);

    let list_migrations = ctx
        .server
        .get_with_auth("/api/v1/admin/migrations?limit=20&offset=0", &token)
        .await;
    assert_status(&list_migrations, StatusCode::OK);

    for endpoint in [
        format!("/api/v1/admin/migrations/{}", migration_id),
        format!("/api/v1/admin/migrations/{}/progress", migration_id),
        format!("/api/v1/admin/migrations/{}/errors", migration_id),
    ] {
        let response = ctx.server.get_with_auth(&endpoint, &token).await;
        assert_status_in(&response, &[StatusCode::OK, StatusCode::NOT_FOUND]);
    }

    for endpoint in [
        format!("/api/v1/admin/migrations/{}/cancel", migration_id),
        format!("/api/v1/admin/migrations/{}/resume", migration_id),
        format!("/api/v1/admin/migrations/{}/pause", migration_id),
    ] {
        let response = ctx.server.post_with_auth(&endpoint, json!({}), &token).await;
        assert_status_in(&response, &[StatusCode::OK, StatusCode::NOT_FOUND]);
    }

    let delete_connection = ctx
        .server
        .delete_with_auth(&format!("/api/v1/admin/directory/ldap/{}", connection_id), &token)
        .await;
    assert_status(&delete_connection, StatusCode::NO_CONTENT);
}
