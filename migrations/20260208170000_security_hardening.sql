-- Security hardening: RLS, admin-only policies, function privileges, and defaults

-- ============================================
-- Remove unsafe admin views and grants
-- ============================================
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE c.relkind = 'v' AND n.nspname = 'public' AND c.relname = 'users_admin'
    ) THEN
        EXECUTE 'REVOKE ALL ON users_admin FROM vault_app';
        EXECUTE 'DROP VIEW users_admin';
    END IF;
END $$;

DO $$
DECLARE
    vname TEXT;
BEGIN
    FOR vname IN SELECT unnest(ARRAY[
        'admin_scim_users',
        'admin_scim_groups',
        'admin_audit_exports',
        'admin_audit_webhooks',
        'admin_directory_connections',
        'admin_security_policies'
    ])
    LOOP
        IF EXISTS (
            SELECT 1 FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE c.relkind = 'v' AND n.nspname = 'public' AND c.relname = vname
        ) THEN
            EXECUTE format('DROP VIEW %I', vname);
        END IF;
    END LOOP;
END $$;

-- ============================================
-- Tenants RLS
-- ============================================
ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenants_select ON tenants;
CREATE POLICY tenants_select ON tenants
    FOR SELECT TO vault_app, vault_readonly
    USING (id = current_tenant_id() OR is_admin());

-- ============================================
-- Admin-only policies for privileged tables
-- ============================================
-- SSO
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

-- Security policies
DROP POLICY IF EXISTS tenant_isolation_security_policies ON security_policies;
CREATE POLICY security_policies_admin_all ON security_policies
    FOR ALL TO vault_app
    USING (tenant_id = current_tenant_id() AND is_admin())
    WITH CHECK (tenant_id = current_tenant_id() AND is_admin());

-- OAuth / OIDC
DROP POLICY IF EXISTS oauth_clients_isolation ON oauth_clients;
CREATE POLICY oauth_clients_admin_all ON oauth_clients
    FOR ALL TO vault_app
    USING (tenant_id = current_tenant_id() AND is_admin())
    WITH CHECK (tenant_id = current_tenant_id() AND is_admin());

DROP POLICY IF EXISTS oauth_codes_isolation ON oauth_authorization_codes;
CREATE POLICY oauth_codes_admin_all ON oauth_authorization_codes
    FOR ALL TO vault_app
    USING (tenant_id = current_tenant_id() AND is_admin())
    WITH CHECK (tenant_id = current_tenant_id() AND is_admin());

DROP POLICY IF EXISTS oauth_tokens_isolation ON oauth_tokens;
CREATE POLICY oauth_tokens_admin_all ON oauth_tokens
    FOR ALL TO vault_app
    USING (tenant_id = current_tenant_id() AND is_admin())
    WITH CHECK (tenant_id = current_tenant_id() AND is_admin());

-- Tenant admins
DROP POLICY IF EXISTS tenant_admins_isolation ON tenant_admins;
CREATE POLICY tenant_admins_admin_all ON tenant_admins
    FOR ALL TO vault_app
    USING (tenant_id = current_tenant_id() AND is_admin())
    WITH CHECK (tenant_id = current_tenant_id() AND is_admin());

DROP POLICY IF EXISTS tenant_admin_invites_isolation ON tenant_admin_invitations;
CREATE POLICY tenant_admin_invites_admin_all ON tenant_admin_invitations
    FOR ALL TO vault_app
    USING (tenant_id = current_tenant_id() AND is_admin())
    WITH CHECK (tenant_id = current_tenant_id() AND is_admin());

-- Log streams
DROP POLICY IF EXISTS log_streams_isolation ON log_streams;
CREATE POLICY log_streams_admin_all ON log_streams
    FOR ALL TO vault_app
    USING (tenant_id = current_tenant_id() AND is_admin())
    WITH CHECK (tenant_id = current_tenant_id() AND is_admin());

DROP POLICY IF EXISTS log_stream_deliveries_isolation ON log_stream_deliveries;
CREATE POLICY log_stream_deliveries_admin_all ON log_stream_deliveries
    FOR ALL TO vault_app
    USING (tenant_id = current_tenant_id() AND is_admin())
    WITH CHECK (tenant_id = current_tenant_id() AND is_admin());

-- Actions
DROP POLICY IF EXISTS actions_isolation ON actions;
CREATE POLICY actions_admin_all ON actions
    FOR ALL TO vault_app
    USING (tenant_id = current_tenant_id() AND is_admin())
    WITH CHECK (tenant_id = current_tenant_id() AND is_admin());

DROP POLICY IF EXISTS action_execs_isolation ON action_executions;
CREATE POLICY action_execs_admin_all ON action_executions
    FOR ALL TO vault_app
    USING (tenant_id = current_tenant_id() AND is_admin())
    WITH CHECK (tenant_id = current_tenant_id() AND is_admin());

-- SCIM (allow SCIM role as well as admin)
DROP POLICY IF EXISTS tenant_isolation_scim_tokens ON scim_tokens;
CREATE POLICY scim_tokens_privileged_all ON scim_tokens
    FOR ALL TO vault_app
    USING (
        tenant_id = current_tenant_id()
        AND (is_admin() OR current_setting('app.current_user_role', true) = 'scim')
    )
    WITH CHECK (
        tenant_id = current_tenant_id()
        AND (is_admin() OR current_setting('app.current_user_role', true) = 'scim')
    );

DROP POLICY IF EXISTS tenant_isolation_scim_mappings ON scim_mappings;
CREATE POLICY scim_mappings_privileged_all ON scim_mappings
    FOR ALL TO vault_app
    USING (
        tenant_id = current_tenant_id()
        AND (is_admin() OR current_setting('app.current_user_role', true) = 'scim')
    )
    WITH CHECK (
        tenant_id = current_tenant_id()
        AND (is_admin() OR current_setting('app.current_user_role', true) = 'scim')
    );

DROP POLICY IF EXISTS tenant_isolation_scim_users ON scim_users;
CREATE POLICY scim_users_privileged_all ON scim_users
    FOR ALL TO vault_app
    USING (
        tenant_id = current_tenant_id()
        AND (is_admin() OR current_setting('app.current_user_role', true) = 'scim')
    )
    WITH CHECK (
        tenant_id = current_tenant_id()
        AND (is_admin() OR current_setting('app.current_user_role', true) = 'scim')
    );

DROP POLICY IF EXISTS tenant_isolation_scim_groups ON scim_groups;
CREATE POLICY scim_groups_privileged_all ON scim_groups
    FOR ALL TO vault_app
    USING (
        tenant_id = current_tenant_id()
        AND (is_admin() OR current_setting('app.current_user_role', true) = 'scim')
    )
    WITH CHECK (
        tenant_id = current_tenant_id()
        AND (is_admin() OR current_setting('app.current_user_role', true) = 'scim')
    );

-- ============================================
-- i18n translations policy tightening
-- ============================================
DROP POLICY IF EXISTS i18n_tenant_isolation ON i18n_translations;

CREATE POLICY i18n_translations_select ON i18n_translations
    FOR SELECT TO vault_app
    USING (
        tenant_id IS NULL
        OR tenant_id = current_setting('app.current_tenant_id', true)::uuid
    );

CREATE POLICY i18n_translations_tenant_write ON i18n_translations
    FOR INSERT, UPDATE, DELETE TO vault_app
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        AND is_admin()
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        AND is_admin()
    );

CREATE POLICY i18n_translations_global_write ON i18n_translations
    FOR INSERT, UPDATE, DELETE TO vault_app
    USING (
        tenant_id IS NULL
        AND (is_admin() OR current_setting('app.current_user_role', true) = 'superadmin')
    )
    WITH CHECK (
        tenant_id IS NULL
        AND (is_admin() OR current_setting('app.current_user_role', true) = 'superadmin')
    );

-- ============================================
-- Default privileges: remove blanket DML grants for vault_app
-- ============================================
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM vault_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON SEQUENCES FROM vault_app;

-- ============================================
-- vault_service should not bypass RLS
-- ============================================
ALTER ROLE vault_service NOBYPASSRLS;
ALTER ROLE vault_service SET row_security = ON;

-- ============================================
-- SECURITY DEFINER hardening
-- ============================================
-- Enforce safe search_path and restrict EXECUTE
ALTER FUNCTION current_tenant_id() SET search_path = pg_catalog, public;
ALTER FUNCTION is_admin() SET search_path = pg_catalog, public;
ALTER FUNCTION check_security_setup() SET search_path = pg_catalog, public;
ALTER FUNCTION get_active_session_count(UUID) SET search_path = pg_catalog, public;
ALTER FUNCTION can_create_session(UUID, UUID, INTEGER) SET search_path = pg_catalog, public;
ALTER FUNCTION revoke_oldest_sessions(UUID, UUID, INTEGER) SET search_path = pg_catalog, public;
ALTER FUNCTION update_user_geo_history(UUID, UUID, VARCHAR, INET) SET search_path = pg_catalog, public;
ALTER FUNCTION log_geo_audit_event(UUID, UUID, UUID, VARCHAR, INET, VARCHAR, BOOLEAN, BOOLEAN, BOOLEAN, TEXT, TEXT, BOOLEAN, JSONB) SET search_path = pg_catalog, public;
ALTER FUNCTION get_tenant_by_custom_domain(TEXT) SET search_path = pg_catalog, public;

-- Controlled SCIM token lookup (bypasses RLS safely for auth bootstrap)
CREATE OR REPLACE FUNCTION get_scim_token_by_hash(p_token_hash TEXT)
RETURNS TABLE (
    id UUID,
    tenant_id UUID,
    token_hash TEXT,
    name VARCHAR(255),
    status VARCHAR(50),
    created_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    created_by UUID
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        t.id,
        t.tenant_id,
        t.token_hash,
        t.name,
        t.status,
        t.created_at,
        t.expires_at,
        t.last_used_at,
        t.created_by
    FROM scim_tokens t
    WHERE t.token_hash = p_token_hash
      AND t.status = 'active';
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public;

REVOKE ALL ON FUNCTION current_tenant_id() FROM PUBLIC;
REVOKE ALL ON FUNCTION is_admin() FROM PUBLIC;
REVOKE ALL ON FUNCTION check_security_setup() FROM PUBLIC;
REVOKE ALL ON FUNCTION get_active_session_count(UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION can_create_session(UUID, UUID, INTEGER) FROM PUBLIC;
REVOKE ALL ON FUNCTION revoke_oldest_sessions(UUID, UUID, INTEGER) FROM PUBLIC;
REVOKE ALL ON FUNCTION update_user_geo_history(UUID, UUID, VARCHAR, INET) FROM PUBLIC;
REVOKE ALL ON FUNCTION log_geo_audit_event(UUID, UUID, UUID, VARCHAR, INET, VARCHAR, BOOLEAN, BOOLEAN, BOOLEAN, TEXT, TEXT, BOOLEAN, JSONB) FROM PUBLIC;
REVOKE ALL ON FUNCTION get_tenant_by_custom_domain(TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION get_scim_token_by_hash(TEXT) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION current_tenant_id() TO vault_app, vault_readonly, vault_service, vault_admin;
GRANT EXECUTE ON FUNCTION is_admin() TO vault_app, vault_readonly, vault_service, vault_admin;
GRANT EXECUTE ON FUNCTION get_active_session_count(UUID) TO vault_app, vault_service;
GRANT EXECUTE ON FUNCTION can_create_session(UUID, UUID, INTEGER) TO vault_app, vault_service;
GRANT EXECUTE ON FUNCTION revoke_oldest_sessions(UUID, UUID, INTEGER) TO vault_app, vault_service;
GRANT EXECUTE ON FUNCTION update_user_geo_history(UUID, UUID, VARCHAR, INET) TO vault_app, vault_service;
GRANT EXECUTE ON FUNCTION log_geo_audit_event(UUID, UUID, UUID, VARCHAR, INET, VARCHAR, BOOLEAN, BOOLEAN, BOOLEAN, TEXT, TEXT, BOOLEAN, JSONB) TO vault_app, vault_service;
GRANT EXECUTE ON FUNCTION get_tenant_by_custom_domain(TEXT) TO vault_app;
GRANT EXECUTE ON FUNCTION get_scim_token_by_hash(TEXT) TO vault_app;
GRANT EXECUTE ON FUNCTION check_security_setup() TO vault_admin;
