-- Instance + Organization settings (layered configuration)

CREATE TABLE IF NOT EXISTS instance_settings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    auth_settings JSONB NOT NULL DEFAULT '{}',
    security_settings JSONB NOT NULL DEFAULT '{}',
    branding_settings JSONB NOT NULL DEFAULT '{}',
    email_settings JSONB NOT NULL DEFAULT '{}',
    oauth_settings JSONB NOT NULL DEFAULT '{}',
    localization_settings JSONB NOT NULL DEFAULT '{}',
    webhook_settings JSONB NOT NULL DEFAULT '{}',
    privacy_settings JSONB NOT NULL DEFAULT '{}',
    advanced_settings JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS organization_settings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    auth_settings JSONB NOT NULL DEFAULT '{}',
    security_settings JSONB NOT NULL DEFAULT '{}',
    branding_settings JSONB NOT NULL DEFAULT '{}',
    email_settings JSONB NOT NULL DEFAULT '{}',
    oauth_settings JSONB NOT NULL DEFAULT '{}',
    localization_settings JSONB NOT NULL DEFAULT '{}',
    webhook_settings JSONB NOT NULL DEFAULT '{}',
    privacy_settings JSONB NOT NULL DEFAULT '{}',
    advanced_settings JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE(tenant_id, organization_id)
);

CREATE INDEX IF NOT EXISTS idx_org_settings_tenant ON organization_settings(tenant_id);
CREATE INDEX IF NOT EXISTS idx_org_settings_org ON organization_settings(organization_id);

ALTER TABLE instance_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE organization_settings ENABLE ROW LEVEL SECURITY;

ALTER TABLE instance_settings FORCE ROW LEVEL SECURITY;
ALTER TABLE organization_settings FORCE ROW LEVEL SECURITY;

-- Policies
DROP POLICY IF EXISTS instance_settings_select ON instance_settings;
CREATE POLICY instance_settings_select ON instance_settings
    FOR SELECT TO vault_app
    USING (is_admin());

DROP POLICY IF EXISTS instance_settings_write ON instance_settings;
CREATE POLICY instance_settings_write ON instance_settings
    FOR INSERT, UPDATE, DELETE TO vault_app
    USING (is_admin())
    WITH CHECK (is_admin());

DROP POLICY IF EXISTS org_settings_select ON organization_settings;
CREATE POLICY org_settings_select ON organization_settings
    FOR SELECT TO vault_app
    USING (
        tenant_id = current_tenant_id()
        AND (is_admin() OR is_org_member(organization_id))
    );

DROP POLICY IF EXISTS org_settings_write ON organization_settings;
CREATE POLICY org_settings_write ON organization_settings
    FOR INSERT, UPDATE, DELETE TO vault_app
    USING (
        tenant_id = current_tenant_id()
        AND (is_admin() OR is_org_admin(organization_id))
    )
    WITH CHECK (tenant_id = current_tenant_id());

-- Effective settings helper
CREATE OR REPLACE FUNCTION get_effective_org_settings(p_tenant_id UUID, p_org_id UUID)
RETURNS JSONB AS $$
DECLARE
    v_instance JSONB;
    v_tenant JSONB;
    v_org JSONB;
BEGIN
    SELECT jsonb_build_object(
        'auth', auth_settings,
        'security', security_settings,
        'branding', branding_settings,
        'email', email_settings,
        'oauth', oauth_settings,
        'localization', localization_settings,
        'webhook', webhook_settings,
        'privacy', privacy_settings,
        'advanced', advanced_settings
    ) INTO v_instance
    FROM instance_settings
    ORDER BY created_at DESC
    LIMIT 1;

    SELECT jsonb_build_object(
        'auth', auth_settings,
        'security', security_settings,
        'branding', branding_settings,
        'email', email_settings,
        'oauth', oauth_settings,
        'localization', localization_settings,
        'webhook', webhook_settings,
        'privacy', privacy_settings,
        'advanced', advanced_settings
    ) INTO v_tenant
    FROM tenant_settings
    WHERE tenant_id = p_tenant_id;

    SELECT jsonb_build_object(
        'auth', auth_settings,
        'security', security_settings,
        'branding', branding_settings,
        'email', email_settings,
        'oauth', oauth_settings,
        'localization', localization_settings,
        'webhook', webhook_settings,
        'privacy', privacy_settings,
        'advanced', advanced_settings
    ) INTO v_org
    FROM organization_settings
    WHERE tenant_id = p_tenant_id AND organization_id = p_org_id;

    RETURN COALESCE(v_instance, '{}'::jsonb) || COALESCE(v_tenant, '{}'::jsonb) || COALESCE(v_org, '{}'::jsonb);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public;

REVOKE ALL ON FUNCTION get_effective_org_settings(UUID, UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION get_effective_org_settings(UUID, UUID) TO vault_app;

-- Triggers
CREATE TRIGGER update_instance_settings_updated_at
    BEFORE UPDATE ON instance_settings
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_org_settings_updated_at
    BEFORE UPDATE ON organization_settings
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Grants
GRANT SELECT, INSERT, UPDATE, DELETE ON instance_settings TO vault_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON organization_settings TO vault_app;
GRANT SELECT ON instance_settings TO vault_readonly;
GRANT SELECT ON organization_settings TO vault_readonly;
