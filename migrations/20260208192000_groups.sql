-- Organization Groups

CREATE TABLE IF NOT EXISTS org_groups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE(organization_id, name)
);

CREATE TABLE IF NOT EXISTS org_group_members (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    group_id UUID NOT NULL REFERENCES org_groups(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE(group_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_org_groups_org ON org_groups(organization_id);
CREATE INDEX IF NOT EXISTS idx_org_groups_tenant ON org_groups(tenant_id);
CREATE INDEX IF NOT EXISTS idx_org_group_members_group ON org_group_members(group_id);
CREATE INDEX IF NOT EXISTS idx_org_group_members_user ON org_group_members(user_id);

ALTER TABLE org_groups ENABLE ROW LEVEL SECURITY;
ALTER TABLE org_group_members ENABLE ROW LEVEL SECURITY;

ALTER TABLE org_groups FORCE ROW LEVEL SECURITY;
ALTER TABLE org_group_members FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS org_groups_select ON org_groups;
CREATE POLICY org_groups_select ON org_groups
    FOR SELECT TO vault_app
    USING (
        tenant_id = current_tenant_id()
        AND (is_admin() OR is_org_member(organization_id))
    );

DROP POLICY IF EXISTS org_groups_write ON org_groups;
CREATE POLICY org_groups_write ON org_groups
    FOR INSERT, UPDATE, DELETE TO vault_app
    USING (
        tenant_id = current_tenant_id()
        AND (is_admin() OR is_org_admin(organization_id))
    )
    WITH CHECK (tenant_id = current_tenant_id());

DROP POLICY IF EXISTS org_group_members_select ON org_group_members;
CREATE POLICY org_group_members_select ON org_group_members
    FOR SELECT TO vault_app
    USING (
        tenant_id = current_tenant_id()
        AND (is_admin() OR is_org_member(organization_id))
    );

DROP POLICY IF EXISTS org_group_members_write ON org_group_members;
CREATE POLICY org_group_members_write ON org_group_members
    FOR INSERT, UPDATE, DELETE TO vault_app
    USING (
        tenant_id = current_tenant_id()
        AND (is_admin() OR is_org_admin(organization_id))
    )
    WITH CHECK (tenant_id = current_tenant_id());

CREATE TRIGGER update_org_groups_updated_at
    BEFORE UPDATE ON org_groups
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

GRANT SELECT, INSERT, UPDATE, DELETE ON org_groups TO vault_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON org_group_members TO vault_app;
GRANT SELECT ON org_groups TO vault_readonly;
GRANT SELECT ON org_group_members TO vault_readonly;
