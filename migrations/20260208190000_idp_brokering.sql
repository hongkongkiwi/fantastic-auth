-- Identity Provider brokering + domain discovery

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'idp_provider_type') THEN
        CREATE TYPE idp_provider_type AS ENUM ('oidc', 'saml', 'google', 'microsoft', 'okta', 'auth0', 'custom');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'idp_provider_status') THEN
        CREATE TYPE idp_provider_status AS ENUM ('active', 'inactive');
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS idp_providers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    application_id UUID REFERENCES applications(id) ON DELETE SET NULL,
    name VARCHAR(255) NOT NULL,
    provider_type idp_provider_type NOT NULL,
    status idp_provider_status NOT NULL DEFAULT 'active',
    config JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE(tenant_id, organization_id, name)
);

CREATE TABLE IF NOT EXISTS idp_domains (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    application_id UUID REFERENCES applications(id) ON DELETE SET NULL,
    provider_id UUID NOT NULL REFERENCES idp_providers(id) ON DELETE CASCADE,
    domain VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE(tenant_id, domain)
);

CREATE TABLE IF NOT EXISTS idp_intents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    application_id UUID REFERENCES applications(id) ON DELETE SET NULL,
    provider_id UUID NOT NULL REFERENCES idp_providers(id) ON DELETE CASCADE,
    state VARCHAR(255) NOT NULL,
    nonce VARCHAR(255),
    redirect_uri TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_idp_providers_tenant ON idp_providers(tenant_id);
CREATE INDEX IF NOT EXISTS idx_idp_providers_org ON idp_providers(organization_id);
CREATE INDEX IF NOT EXISTS idx_idp_providers_app ON idp_providers(application_id);
CREATE INDEX IF NOT EXISTS idx_idp_domains_domain ON idp_domains(domain);
CREATE INDEX IF NOT EXISTS idx_idp_domains_provider ON idp_domains(provider_id);
CREATE INDEX IF NOT EXISTS idx_idp_intents_state ON idp_intents(state);
CREATE INDEX IF NOT EXISTS idx_idp_intents_expires ON idp_intents(expires_at);

ALTER TABLE idp_providers ENABLE ROW LEVEL SECURITY;
ALTER TABLE idp_domains ENABLE ROW LEVEL SECURITY;
ALTER TABLE idp_intents ENABLE ROW LEVEL SECURITY;

ALTER TABLE idp_providers FORCE ROW LEVEL SECURITY;
ALTER TABLE idp_domains FORCE ROW LEVEL SECURITY;
ALTER TABLE idp_intents FORCE ROW LEVEL SECURITY;

-- Policies
DROP POLICY IF EXISTS idp_providers_select ON idp_providers;
CREATE POLICY idp_providers_select ON idp_providers
    FOR SELECT TO vault_app
    USING (
        tenant_id = current_tenant_id()
        AND (is_admin() OR is_org_member(organization_id))
    );

DROP POLICY IF EXISTS idp_providers_write ON idp_providers;
CREATE POLICY idp_providers_write ON idp_providers
    FOR INSERT, UPDATE, DELETE TO vault_app
    USING (
        tenant_id = current_tenant_id()
        AND (is_admin() OR is_org_admin(organization_id))
    )
    WITH CHECK (tenant_id = current_tenant_id());

DROP POLICY IF EXISTS idp_domains_select ON idp_domains;
CREATE POLICY idp_domains_select ON idp_domains
    FOR SELECT TO vault_app
    USING (
        tenant_id = current_tenant_id()
        AND (is_admin() OR is_org_member(organization_id))
    );

DROP POLICY IF EXISTS idp_domains_write ON idp_domains;
CREATE POLICY idp_domains_write ON idp_domains
    FOR INSERT, UPDATE, DELETE TO vault_app
    USING (
        tenant_id = current_tenant_id()
        AND (is_admin() OR is_org_admin(organization_id))
    )
    WITH CHECK (tenant_id = current_tenant_id());

DROP POLICY IF EXISTS idp_intents_select ON idp_intents;
CREATE POLICY idp_intents_select ON idp_intents
    FOR SELECT TO vault_app
    USING (tenant_id = current_tenant_id());

DROP POLICY IF EXISTS idp_intents_write ON idp_intents;
CREATE POLICY idp_intents_write ON idp_intents
    FOR INSERT, UPDATE, DELETE TO vault_app
    USING (tenant_id = current_tenant_id())
    WITH CHECK (tenant_id = current_tenant_id());

-- Domain discovery helper (bypass RLS safely)
CREATE OR REPLACE FUNCTION get_idp_provider_by_domain(p_domain TEXT)
RETURNS TABLE (
    provider_id UUID,
    tenant_id UUID,
    organization_id UUID,
    application_id UUID,
    provider_type idp_provider_type,
    status idp_provider_status,
    config JSONB
) AS $$
BEGIN
    RETURN QUERY
    SELECT p.id, p.tenant_id, p.organization_id, p.application_id, p.provider_type, p.status, p.config
    FROM idp_domains d
    JOIN idp_providers p ON p.id = d.provider_id
    WHERE d.domain = p_domain
      AND p.status = 'active';
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public;

REVOKE ALL ON FUNCTION get_idp_provider_by_domain(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION get_idp_provider_by_domain(TEXT) TO vault_app;

-- Triggers
CREATE TRIGGER update_idp_providers_updated_at
    BEFORE UPDATE ON idp_providers
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Grants
GRANT SELECT, INSERT, UPDATE, DELETE ON idp_providers TO vault_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON idp_domains TO vault_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON idp_intents TO vault_app;

GRANT SELECT ON idp_providers TO vault_readonly;
GRANT SELECT ON idp_domains TO vault_readonly;
GRANT SELECT ON idp_intents TO vault_readonly;
