-- Admin views for sensitive tables (reads via views in admin routes)

CREATE OR REPLACE VIEW admin_webhook_endpoints AS
SELECT * FROM webhook_endpoints;

CREATE OR REPLACE VIEW admin_webhook_deliveries AS
SELECT * FROM webhook_deliveries;

CREATE OR REPLACE VIEW admin_mfa_credentials AS
SELECT * FROM mfa_credentials;

CREATE OR REPLACE VIEW admin_mfa_backup_codes AS
SELECT * FROM mfa_backup_codes;

CREATE OR REPLACE VIEW admin_oauth_connections AS
SELECT * FROM oauth_connections;

CREATE OR REPLACE VIEW admin_refresh_tokens AS
SELECT * FROM refresh_tokens;

CREATE OR REPLACE VIEW admin_magic_links AS
SELECT * FROM magic_links;

CREATE OR REPLACE VIEW admin_email_verifications AS
SELECT * FROM email_verifications;

CREATE OR REPLACE VIEW admin_password_resets AS
SELECT * FROM password_resets;

CREATE OR REPLACE VIEW admin_subscriptions AS
SELECT * FROM subscriptions;

CREATE OR REPLACE VIEW admin_payment_methods AS
SELECT * FROM payment_methods;

CREATE OR REPLACE VIEW admin_invoices AS
SELECT * FROM invoices;

CREATE OR REPLACE VIEW admin_usage_records AS
SELECT * FROM usage_records;

CREATE OR REPLACE VIEW admin_billing_events AS
SELECT * FROM billing_events;

CREATE OR REPLACE VIEW admin_sso_connections AS
SELECT * FROM sso_connections;

CREATE OR REPLACE VIEW admin_sso_domains AS
SELECT * FROM sso_domains;

CREATE OR REPLACE VIEW admin_org_sso_settings AS
SELECT * FROM org_sso_settings;

CREATE OR REPLACE VIEW admin_organization_domains AS
SELECT * FROM organization_domains;

CREATE OR REPLACE VIEW admin_organization_roles AS
SELECT * FROM organization_roles;

CREATE OR REPLACE VIEW admin_tenant_branding AS
SELECT * FROM tenant_branding;

CREATE OR REPLACE VIEW admin_tenant_themes AS
SELECT * FROM tenant_themes;

CREATE OR REPLACE VIEW admin_scim_tokens AS
SELECT * FROM scim_tokens;

CREATE OR REPLACE VIEW admin_scim_mappings AS
SELECT * FROM scim_mappings;

CREATE OR REPLACE VIEW admin_scim_users AS
SELECT * FROM scim_users;

CREATE OR REPLACE VIEW admin_scim_groups AS
SELECT * FROM scim_groups;

CREATE OR REPLACE VIEW admin_audit_exports AS
SELECT * FROM audit_exports;

CREATE OR REPLACE VIEW admin_audit_webhooks AS
SELECT * FROM audit_webhooks;

CREATE OR REPLACE VIEW admin_directory_connections AS
SELECT * FROM directory_connections;

CREATE OR REPLACE VIEW admin_security_policies AS
SELECT * FROM security_policies;
