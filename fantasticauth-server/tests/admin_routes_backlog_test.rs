//! Admin route backlog integration test skeleton.
//!
//! Each test is intentionally ignored until implemented.

macro_rules! backlog_test {
    ($name:ident, $target:expr) => {
        #[tokio::test]
        #[ignore = "backlog: implement integration assertions"]
        async fn $name() {
            todo!("Implement coverage for {}", $target);
        }
    };
}

backlog_test!(test_admin_actions_routes, "routes/admin/actions.rs");
backlog_test!(test_admin_analytics_routes, "routes/admin/analytics.rs");
backlog_test!(test_admin_applications_routes, "routes/admin/applications.rs");
backlog_test!(test_admin_audit_exports_routes, "routes/admin/audit_exports.rs");
backlog_test!(test_admin_audit_logs_routes, "routes/admin/audit_logs.rs");
backlog_test!(test_admin_branding_routes, "routes/admin/branding.rs");
backlog_test!(test_admin_bulk_routes, "routes/admin/bulk.rs");
backlog_test!(test_admin_consent_routes, "routes/admin/consent.rs");
backlog_test!(test_admin_custom_domains_routes, "routes/admin/custom_domains.rs");
backlog_test!(test_admin_dashboard_routes, "routes/admin/dashboard.rs");
backlog_test!(test_admin_device_flow_routes, "routes/admin/device_flow.rs");
backlog_test!(test_admin_directory_routes, "routes/admin/directory.rs");
backlog_test!(test_admin_domains_routes, "routes/admin/domains.rs");
backlog_test!(test_admin_email_templates_routes, "routes/admin/email_templates.rs");
backlog_test!(test_admin_federation_routes, "routes/admin/federation.rs");
backlog_test!(test_admin_groups_routes, "routes/admin/groups.rs");
backlog_test!(test_admin_i18n_routes, "routes/admin/i18n.rs");
backlog_test!(test_admin_idp_routes, "routes/admin/idp.rs");
backlog_test!(test_admin_impersonation_routes, "routes/admin/impersonation.rs");
backlog_test!(test_admin_keys_routes, "routes/admin/keys.rs");
backlog_test!(test_admin_log_streams_routes, "routes/admin/log_streams.rs");
backlog_test!(test_admin_m2m_routes, "routes/admin/m2m.rs");
backlog_test!(test_admin_migrations_routes, "routes/admin/migrations.rs");
backlog_test!(test_admin_oidc_clients_routes, "routes/admin/oidc_clients.rs");
backlog_test!(test_admin_oidc_routes, "routes/admin/oidc.rs");
backlog_test!(test_admin_org_settings_routes, "routes/admin/org_settings.rs");
backlog_test!(test_admin_password_policy_routes, "routes/admin/password_policy.rs");
backlog_test!(test_admin_projects_routes, "routes/admin/projects.rs");
backlog_test!(test_admin_push_mfa_routes, "routes/admin/push_mfa.rs");
backlog_test!(test_admin_rate_limits_routes, "routes/admin/rate_limits.rs");
backlog_test!(test_admin_risk_routes, "routes/admin/risk.rs");
backlog_test!(test_admin_roles_routes, "routes/admin/roles.rs");
backlog_test!(test_admin_scim_routes, "routes/admin/scim.rs");
backlog_test!(test_admin_security_policies_routes, "routes/admin/security_policies.rs");
backlog_test!(test_admin_settings_routes, "routes/admin/settings.rs");
backlog_test!(test_admin_settings_v2_routes, "routes/admin/settings_v2.rs");
backlog_test!(test_admin_system_routes, "routes/admin/system.rs");
backlog_test!(test_admin_tenant_admins_routes, "routes/admin/tenant_admins.rs");
backlog_test!(test_admin_webhooks_routes, "routes/admin/webhooks.rs");
