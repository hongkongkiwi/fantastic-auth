-- Tighten RLS for admin-only and self-only tables

-- Organization invitations (admin-only)
DROP POLICY IF EXISTS tenant_isolation_org_invitations ON organization_invitations;
CREATE POLICY org_invitations_admin_all ON organization_invitations
    FOR ALL TO vault_app
    USING (tenant_id = current_tenant_id() AND is_admin())
    WITH CHECK (tenant_id = current_tenant_id() AND is_admin());

-- Organizations (members can read, admins manage)
DROP POLICY IF EXISTS orgs_select ON organizations;
DROP POLICY IF EXISTS orgs_insert ON organizations;
DROP POLICY IF EXISTS orgs_update ON organizations;
DROP POLICY IF EXISTS orgs_delete ON organizations;

CREATE POLICY orgs_select_membership ON organizations
    FOR SELECT TO vault_app
    USING (
        tenant_id = current_tenant_id()
        AND deleted_at IS NULL
        AND (
            is_admin()
            OR EXISTS (
                SELECT 1
                FROM organization_members m
                WHERE m.organization_id = organizations.id
                  AND m.tenant_id = current_tenant_id()
                  AND m.user_id = current_setting('app.current_user_id', TRUE)::UUID
                  AND m.status = 'active'
            )
        )
    );

CREATE POLICY orgs_insert_admin ON organizations
    FOR INSERT TO vault_app
    WITH CHECK (tenant_id = current_tenant_id() AND is_admin());

CREATE POLICY orgs_update_admin ON organizations
    FOR UPDATE TO vault_app
    USING (tenant_id = current_tenant_id() AND is_admin())
    WITH CHECK (tenant_id = current_tenant_id());

CREATE POLICY orgs_delete_admin ON organizations
    FOR DELETE TO vault_app
    USING (tenant_id = current_tenant_id() AND is_admin());

-- Organization members (members can read roster, admins manage, users can update self)
DROP POLICY IF EXISTS org_members_select ON organization_members;
DROP POLICY IF EXISTS org_members_insert ON organization_members;
DROP POLICY IF EXISTS org_members_update ON organization_members;
DROP POLICY IF EXISTS org_members_delete ON organization_members;

CREATE POLICY org_members_select_roster ON organization_members
    FOR SELECT TO vault_app
    USING (
        tenant_id = current_tenant_id()
        AND (
            is_admin()
            OR user_id = current_setting('app.current_user_id', TRUE)::UUID
            OR EXISTS (
                SELECT 1
                FROM organization_members m
                WHERE m.organization_id = organization_members.organization_id
                  AND m.tenant_id = current_tenant_id()
                  AND m.user_id = current_setting('app.current_user_id', TRUE)::UUID
                  AND m.status = 'active'
            )
        )
    );

CREATE POLICY org_members_insert_admin ON organization_members
    FOR INSERT TO vault_app
    WITH CHECK (tenant_id = current_tenant_id() AND is_admin());

CREATE POLICY org_members_update_self_or_admin ON organization_members
    FOR UPDATE TO vault_app
    USING (
        tenant_id = current_tenant_id()
        AND (is_admin() OR user_id = current_setting('app.current_user_id', TRUE)::UUID)
    )
    WITH CHECK (tenant_id = current_tenant_id());

CREATE POLICY org_members_delete_admin ON organization_members
    FOR DELETE TO vault_app
    USING (tenant_id = current_tenant_id() AND is_admin());

-- OAuth connections (self or admin)
DROP POLICY IF EXISTS tenant_isolation_oauth ON oauth_connections;
CREATE POLICY oauth_connections_select ON oauth_connections
    FOR SELECT TO vault_app
    USING (
        tenant_id = current_tenant_id()
        AND (is_admin() OR user_id = current_setting('app.current_user_id', TRUE)::UUID)
    );
CREATE POLICY oauth_connections_insert ON oauth_connections
    FOR INSERT TO vault_app
    WITH CHECK (
        tenant_id = current_tenant_id()
        AND (is_admin() OR user_id = current_setting('app.current_user_id', TRUE)::UUID)
    );
CREATE POLICY oauth_connections_update ON oauth_connections
    FOR UPDATE TO vault_app
    USING (
        tenant_id = current_tenant_id()
        AND (is_admin() OR user_id = current_setting('app.current_user_id', TRUE)::UUID)
    )
    WITH CHECK (tenant_id = current_tenant_id());
CREATE POLICY oauth_connections_delete ON oauth_connections
    FOR DELETE TO vault_app
    USING (
        tenant_id = current_tenant_id()
        AND (is_admin() OR user_id = current_setting('app.current_user_id', TRUE)::UUID)
    );

-- Token tables (self or admin)
DROP POLICY IF EXISTS tenant_isolation_refresh_tokens ON refresh_tokens;
CREATE POLICY refresh_tokens_select ON refresh_tokens
    FOR SELECT TO vault_app
    USING (
        tenant_id = current_tenant_id()
        AND (is_admin() OR user_id = current_setting('app.current_user_id', TRUE)::UUID)
    );
CREATE POLICY refresh_tokens_insert ON refresh_tokens
    FOR INSERT TO vault_app
    WITH CHECK (
        tenant_id = current_tenant_id()
        AND (is_admin() OR user_id = current_setting('app.current_user_id', TRUE)::UUID)
    );
CREATE POLICY refresh_tokens_update ON refresh_tokens
    FOR UPDATE TO vault_app
    USING (
        tenant_id = current_tenant_id()
        AND (is_admin() OR user_id = current_setting('app.current_user_id', TRUE)::UUID)
    )
    WITH CHECK (tenant_id = current_tenant_id());
CREATE POLICY refresh_tokens_delete ON refresh_tokens
    FOR DELETE TO vault_app
    USING (
        tenant_id = current_tenant_id()
        AND (is_admin() OR user_id = current_setting('app.current_user_id', TRUE)::UUID)
    );

DROP POLICY IF EXISTS tenant_isolation_magic_links ON magic_links;
CREATE POLICY magic_links_select ON magic_links
    FOR SELECT TO vault_app
    USING (
        tenant_id = current_tenant_id()
        AND (is_admin() OR user_id = current_setting('app.current_user_id', TRUE)::UUID)
    );
CREATE POLICY magic_links_insert ON magic_links
    FOR INSERT TO vault_app
    WITH CHECK (
        tenant_id = current_tenant_id()
        AND (is_admin() OR user_id = current_setting('app.current_user_id', TRUE)::UUID)
    );
CREATE POLICY magic_links_update ON magic_links
    FOR UPDATE TO vault_app
    USING (
        tenant_id = current_tenant_id()
        AND (is_admin() OR user_id = current_setting('app.current_user_id', TRUE)::UUID)
    )
    WITH CHECK (tenant_id = current_tenant_id());
CREATE POLICY magic_links_delete ON magic_links
    FOR DELETE TO vault_app
    USING (
        tenant_id = current_tenant_id()
        AND (is_admin() OR user_id = current_setting('app.current_user_id', TRUE)::UUID)
    );

DROP POLICY IF EXISTS tenant_isolation_email_verifications ON email_verifications;
CREATE POLICY email_verifications_select ON email_verifications
    FOR SELECT TO vault_app
    USING (
        tenant_id = current_tenant_id()
        AND (is_admin() OR user_id = current_setting('app.current_user_id', TRUE)::UUID)
    );
CREATE POLICY email_verifications_insert ON email_verifications
    FOR INSERT TO vault_app
    WITH CHECK (
        tenant_id = current_tenant_id()
        AND (is_admin() OR user_id = current_setting('app.current_user_id', TRUE)::UUID)
    );
CREATE POLICY email_verifications_update ON email_verifications
    FOR UPDATE TO vault_app
    USING (
        tenant_id = current_tenant_id()
        AND (is_admin() OR user_id = current_setting('app.current_user_id', TRUE)::UUID)
    )
    WITH CHECK (tenant_id = current_tenant_id());
CREATE POLICY email_verifications_delete ON email_verifications
    FOR DELETE TO vault_app
    USING (
        tenant_id = current_tenant_id()
        AND (is_admin() OR user_id = current_setting('app.current_user_id', TRUE)::UUID)
    );

DROP POLICY IF EXISTS tenant_isolation_password_resets ON password_resets;
CREATE POLICY password_resets_select ON password_resets
    FOR SELECT TO vault_app
    USING (
        tenant_id = current_tenant_id()
        AND (is_admin() OR user_id = current_setting('app.current_user_id', TRUE)::UUID)
    );
CREATE POLICY password_resets_insert ON password_resets
    FOR INSERT TO vault_app
    WITH CHECK (
        tenant_id = current_tenant_id()
        AND (is_admin() OR user_id = current_setting('app.current_user_id', TRUE)::UUID)
    );
CREATE POLICY password_resets_update ON password_resets
    FOR UPDATE TO vault_app
    USING (
        tenant_id = current_tenant_id()
        AND (is_admin() OR user_id = current_setting('app.current_user_id', TRUE)::UUID)
    )
    WITH CHECK (tenant_id = current_tenant_id());
CREATE POLICY password_resets_delete ON password_resets
    FOR DELETE TO vault_app
    USING (
        tenant_id = current_tenant_id()
        AND (is_admin() OR user_id = current_setting('app.current_user_id', TRUE)::UUID)
    );

-- MFA credentials (self or admin)
DROP POLICY IF EXISTS tenant_isolation_mfa_credentials ON mfa_credentials;
CREATE POLICY mfa_credentials_select ON mfa_credentials
    FOR SELECT TO vault_app
    USING (
        tenant_id = current_tenant_id()
        AND (is_admin() OR user_id = current_setting('app.current_user_id', TRUE)::UUID)
    );
CREATE POLICY mfa_credentials_insert ON mfa_credentials
    FOR INSERT TO vault_app
    WITH CHECK (
        tenant_id = current_tenant_id()
        AND (is_admin() OR user_id = current_setting('app.current_user_id', TRUE)::UUID)
    );
CREATE POLICY mfa_credentials_update ON mfa_credentials
    FOR UPDATE TO vault_app
    USING (
        tenant_id = current_tenant_id()
        AND (is_admin() OR user_id = current_setting('app.current_user_id', TRUE)::UUID)
    )
    WITH CHECK (tenant_id = current_tenant_id());
CREATE POLICY mfa_credentials_delete ON mfa_credentials
    FOR DELETE TO vault_app
    USING (
        tenant_id = current_tenant_id()
        AND (is_admin() OR user_id = current_setting('app.current_user_id', TRUE)::UUID)
    );

DROP POLICY IF EXISTS tenant_isolation_mfa_backup_codes ON mfa_backup_codes;
CREATE POLICY mfa_backup_codes_select ON mfa_backup_codes
    FOR SELECT TO vault_app
    USING (
        tenant_id = current_tenant_id()
        AND (is_admin() OR user_id = current_setting('app.current_user_id', TRUE)::UUID)
    );
CREATE POLICY mfa_backup_codes_insert ON mfa_backup_codes
    FOR INSERT TO vault_app
    WITH CHECK (
        tenant_id = current_tenant_id()
        AND (is_admin() OR user_id = current_setting('app.current_user_id', TRUE)::UUID)
    );
CREATE POLICY mfa_backup_codes_update ON mfa_backup_codes
    FOR UPDATE TO vault_app
    USING (
        tenant_id = current_tenant_id()
        AND (is_admin() OR user_id = current_setting('app.current_user_id', TRUE)::UUID)
    )
    WITH CHECK (tenant_id = current_tenant_id());
CREATE POLICY mfa_backup_codes_delete ON mfa_backup_codes
    FOR DELETE TO vault_app
    USING (
        tenant_id = current_tenant_id()
        AND (is_admin() OR user_id = current_setting('app.current_user_id', TRUE)::UUID)
    );

-- Admin-only enterprise tables
DROP POLICY IF EXISTS tenant_isolation_sso_connections ON sso_connections;
CREATE POLICY sso_connections_admin_all ON sso_connections
    FOR ALL TO vault_app
    USING (tenant_id = current_tenant_id() AND is_admin())
    WITH CHECK (tenant_id = current_tenant_id() AND is_admin());

DROP POLICY IF EXISTS tenant_isolation_sso_domains ON sso_domains;
CREATE POLICY sso_domains_admin_all ON sso_domains
    FOR ALL TO vault_app
    USING (tenant_id = current_tenant_id() AND is_admin())
    WITH CHECK (tenant_id = current_tenant_id() AND is_admin());

DROP POLICY IF EXISTS tenant_isolation_org_sso_settings ON org_sso_settings;
CREATE POLICY org_sso_settings_admin_all ON org_sso_settings
    FOR ALL TO vault_app
    USING (tenant_id = current_tenant_id() AND is_admin())
    WITH CHECK (tenant_id = current_tenant_id() AND is_admin());

DROP POLICY IF EXISTS tenant_isolation_org_domains ON organization_domains;
CREATE POLICY organization_domains_admin_all ON organization_domains
    FOR ALL TO vault_app
    USING (tenant_id = current_tenant_id() AND is_admin())
    WITH CHECK (tenant_id = current_tenant_id() AND is_admin());

DROP POLICY IF EXISTS tenant_isolation_org_roles ON organization_roles;
CREATE POLICY organization_roles_admin_all ON organization_roles
    FOR ALL TO vault_app
    USING (tenant_id = current_tenant_id() AND is_admin())
    WITH CHECK (tenant_id = current_tenant_id() AND is_admin());

DROP POLICY IF EXISTS tenant_isolation_branding ON tenant_branding;
CREATE POLICY tenant_branding_admin_all ON tenant_branding
    FOR ALL TO vault_app
    USING (tenant_id = current_tenant_id() AND is_admin())
    WITH CHECK (tenant_id = current_tenant_id() AND is_admin());

DROP POLICY IF EXISTS tenant_isolation_themes ON tenant_themes;
CREATE POLICY tenant_themes_admin_all ON tenant_themes
    FOR ALL TO vault_app
    USING (tenant_id = current_tenant_id() AND is_admin())
    WITH CHECK (tenant_id = current_tenant_id() AND is_admin());

DROP POLICY IF EXISTS tenant_isolation_scim_tokens ON scim_tokens;
CREATE POLICY scim_tokens_admin_all ON scim_tokens
    FOR ALL TO vault_app
    USING (tenant_id = current_tenant_id() AND is_admin())
    WITH CHECK (tenant_id = current_tenant_id() AND is_admin());

DROP POLICY IF EXISTS tenant_isolation_scim_mappings ON scim_mappings;
CREATE POLICY scim_mappings_admin_all ON scim_mappings
    FOR ALL TO vault_app
    USING (tenant_id = current_tenant_id() AND is_admin())
    WITH CHECK (tenant_id = current_tenant_id() AND is_admin());

DROP POLICY IF EXISTS tenant_isolation_scim_users ON scim_users;
CREATE POLICY scim_users_admin_all ON scim_users
    FOR ALL TO vault_app
    USING (tenant_id = current_tenant_id() AND is_admin())
    WITH CHECK (tenant_id = current_tenant_id() AND is_admin());

DROP POLICY IF EXISTS tenant_isolation_scim_groups ON scim_groups;
CREATE POLICY scim_groups_admin_all ON scim_groups
    FOR ALL TO vault_app
    USING (tenant_id = current_tenant_id() AND is_admin())
    WITH CHECK (tenant_id = current_tenant_id() AND is_admin());

DROP POLICY IF EXISTS tenant_isolation_audit_exports ON audit_exports;
CREATE POLICY audit_exports_admin_all ON audit_exports
    FOR ALL TO vault_app
    USING (tenant_id = current_tenant_id() AND is_admin())
    WITH CHECK (tenant_id = current_tenant_id() AND is_admin());

DROP POLICY IF EXISTS tenant_isolation_audit_webhooks ON audit_webhooks;
CREATE POLICY audit_webhooks_admin_all ON audit_webhooks
    FOR ALL TO vault_app
    USING (tenant_id = current_tenant_id() AND is_admin())
    WITH CHECK (tenant_id = current_tenant_id() AND is_admin());

DROP POLICY IF EXISTS tenant_isolation_directory_connections ON directory_connections;
CREATE POLICY directory_connections_admin_all ON directory_connections
    FOR ALL TO vault_app
    USING (tenant_id = current_tenant_id() AND is_admin())
    WITH CHECK (tenant_id = current_tenant_id() AND is_admin());

DROP POLICY IF EXISTS tenant_isolation_security_policies ON security_policies;
CREATE POLICY security_policies_admin_all ON security_policies
    FOR ALL TO vault_app
    USING (tenant_id = current_tenant_id() AND is_admin())
    WITH CHECK (tenant_id = current_tenant_id() AND is_admin());

-- Webhooks (admin-only)
DROP POLICY IF EXISTS tenant_isolation_webhook_endpoints ON webhook_endpoints;
CREATE POLICY webhook_endpoints_admin_all ON webhook_endpoints
    FOR ALL TO vault_app
    USING (tenant_id = current_tenant_id() AND is_admin())
    WITH CHECK (tenant_id = current_tenant_id() AND is_admin());

DROP POLICY IF EXISTS tenant_isolation_webhook_deliveries ON webhook_deliveries;
CREATE POLICY webhook_deliveries_admin_all ON webhook_deliveries
    FOR ALL TO vault_app
    USING (tenant_id = current_tenant_id() AND is_admin())
    WITH CHECK (tenant_id = current_tenant_id() AND is_admin());

-- Billing (admin-only)
DROP POLICY IF EXISTS tenant_isolation_subscriptions ON subscriptions;
CREATE POLICY subscriptions_admin_all ON subscriptions
    FOR ALL TO vault_app
    USING (tenant_id = current_tenant_id() AND is_admin())
    WITH CHECK (tenant_id = current_tenant_id() AND is_admin());

DROP POLICY IF EXISTS tenant_isolation_payment_methods ON payment_methods;
CREATE POLICY payment_methods_admin_all ON payment_methods
    FOR ALL TO vault_app
    USING (tenant_id = current_tenant_id() AND is_admin())
    WITH CHECK (tenant_id = current_tenant_id() AND is_admin());

DROP POLICY IF EXISTS tenant_isolation_invoices ON invoices;
CREATE POLICY invoices_admin_all ON invoices
    FOR ALL TO vault_app
    USING (tenant_id = current_tenant_id() AND is_admin())
    WITH CHECK (tenant_id = current_tenant_id() AND is_admin());

DROP POLICY IF EXISTS tenant_isolation_usage_records ON usage_records;
CREATE POLICY usage_records_admin_all ON usage_records
    FOR ALL TO vault_app
    USING (tenant_id = current_tenant_id() AND is_admin())
    WITH CHECK (tenant_id = current_tenant_id() AND is_admin());

DROP POLICY IF EXISTS tenant_isolation_billing_events ON billing_events;
CREATE POLICY billing_events_admin_all ON billing_events
    FOR ALL TO vault_app
    USING (tenant_id = current_tenant_id() AND is_admin())
    WITH CHECK (tenant_id = current_tenant_id() AND is_admin());
