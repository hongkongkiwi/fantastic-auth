-- Tighten core RLS policies (replace permissive FOR ALL policies)

-- Users
DROP POLICY IF EXISTS tenant_isolation_users ON users;
DROP POLICY IF EXISTS active_users_only ON users;

CREATE POLICY users_select ON users
    FOR SELECT TO vault_app
    USING (
        tenant_id = current_tenant_id()
        AND (deleted_at IS NULL OR is_admin())
        AND (is_admin() OR id = current_setting('app.current_user_id', TRUE)::UUID)
    );

CREATE POLICY users_insert ON users
    FOR INSERT TO vault_app
    WITH CHECK (tenant_id = current_tenant_id());

CREATE POLICY users_update ON users
    FOR UPDATE TO vault_app
    USING (tenant_id = current_tenant_id() AND (is_admin() OR id = current_setting('app.current_user_id', TRUE)::UUID))
    WITH CHECK (tenant_id = current_tenant_id());

CREATE POLICY users_delete ON users
    FOR DELETE TO vault_app
    USING (tenant_id = current_tenant_id() AND is_admin());

-- Sessions
DROP POLICY IF EXISTS tenant_isolation_sessions ON sessions;
DROP POLICY IF EXISTS own_sessions_only ON sessions;

CREATE POLICY sessions_select ON sessions
    FOR SELECT TO vault_app
    USING (
        tenant_id = current_tenant_id()
        AND (is_admin() OR user_id = current_setting('app.current_user_id', TRUE)::UUID)
    );

CREATE POLICY sessions_insert ON sessions
    FOR INSERT TO vault_app
    WITH CHECK (tenant_id = current_tenant_id());

CREATE POLICY sessions_update ON sessions
    FOR UPDATE TO vault_app
    USING (
        tenant_id = current_tenant_id()
        AND (is_admin() OR user_id = current_setting('app.current_user_id', TRUE)::UUID)
    )
    WITH CHECK (tenant_id = current_tenant_id());

CREATE POLICY sessions_delete ON sessions
    FOR DELETE TO vault_app
    USING (
        tenant_id = current_tenant_id()
        AND (is_admin() OR user_id = current_setting('app.current_user_id', TRUE)::UUID)
    );

-- Organizations
DROP POLICY IF EXISTS tenant_isolation_orgs ON organizations;

CREATE POLICY orgs_select ON organizations
    FOR SELECT TO vault_app
    USING (tenant_id = current_tenant_id() AND deleted_at IS NULL);

CREATE POLICY orgs_insert ON organizations
    FOR INSERT TO vault_app
    WITH CHECK (tenant_id = current_tenant_id() AND is_admin());

CREATE POLICY orgs_update ON organizations
    FOR UPDATE TO vault_app
    USING (tenant_id = current_tenant_id() AND is_admin())
    WITH CHECK (tenant_id = current_tenant_id());

CREATE POLICY orgs_delete ON organizations
    FOR DELETE TO vault_app
    USING (tenant_id = current_tenant_id() AND is_admin());

-- Organization members
DROP POLICY IF EXISTS tenant_isolation_org_members ON organization_members;
DROP POLICY IF EXISTS own_membership_update ON organization_members;

CREATE POLICY org_members_select ON organization_members
    FOR SELECT TO vault_app
    USING (
        tenant_id = current_tenant_id()
        AND (is_admin() OR user_id = current_setting('app.current_user_id', TRUE)::UUID)
    );

CREATE POLICY org_members_insert ON organization_members
    FOR INSERT TO vault_app
    WITH CHECK (tenant_id = current_tenant_id() AND is_admin());

CREATE POLICY org_members_update ON organization_members
    FOR UPDATE TO vault_app
    USING (
        tenant_id = current_tenant_id()
        AND (is_admin() OR user_id = current_setting('app.current_user_id', TRUE)::UUID)
    )
    WITH CHECK (tenant_id = current_tenant_id());

CREATE POLICY org_members_delete ON organization_members
    FOR DELETE TO vault_app
    USING (
        tenant_id = current_tenant_id()
        AND (is_admin() OR user_id = current_setting('app.current_user_id', TRUE)::UUID)
    );

-- Audit logs
DROP POLICY IF EXISTS tenant_isolation_audit ON audit_logs;
DROP POLICY IF EXISTS audit_visibility ON audit_logs;

CREATE POLICY audit_select ON audit_logs
    FOR SELECT TO vault_app
    USING (
        tenant_id = current_tenant_id()
        AND (is_admin() OR user_id = current_setting('app.current_user_id', TRUE)::UUID)
    );

CREATE POLICY audit_insert ON audit_logs
    FOR INSERT TO vault_app
    WITH CHECK (tenant_id = current_tenant_id());

-- Keys (restrict to admin)
DROP POLICY IF EXISTS tenant_isolation_keys ON keys;
CREATE POLICY keys_select ON keys
    FOR SELECT TO vault_app
    USING (tenant_id = current_tenant_id() AND is_active = TRUE AND is_admin());
