-- Federation tables for Identity Brokering
-- This migration creates tables for managing federated identity providers

-- Provider types enum
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'federation_provider_type') THEN
        CREATE TYPE federation_provider_type AS ENUM ('saml', 'oidc', 'ldap');
    END IF;
END $$;

-- Federated providers table
CREATE TABLE IF NOT EXISTS federated_providers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    organization_id UUID REFERENCES organizations(id) ON DELETE SET NULL,
    name VARCHAR(255) NOT NULL,
    provider_type federation_provider_type NOT NULL,
    config JSONB NOT NULL DEFAULT '{}',
    enabled BOOLEAN DEFAULT true,
    priority INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ,

    UNIQUE(tenant_id, name)
);

-- Realm mappings table (Home Realm Discovery)
CREATE TABLE IF NOT EXISTS realm_mappings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    domain VARCHAR(255) NOT NULL,
    provider_id UUID NOT NULL REFERENCES federated_providers(id) ON DELETE CASCADE,
    is_default BOOLEAN DEFAULT false,
    created_at TIMESTAMPTZ DEFAULT NOW(),

    UNIQUE(tenant_id, domain)
);

-- Trust relationships table
CREATE TABLE IF NOT EXISTS trust_relationships (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    provider_id UUID NOT NULL REFERENCES federated_providers(id) ON DELETE CASCADE,
    metadata_url TEXT,
    metadata_xml TEXT,
    certificate_fingerprint VARCHAR(255),
    trust_level VARCHAR(20) NOT NULL DEFAULT 'partial', -- 'full', 'partial', 'minimal'
    auto_provision_users BOOLEAN DEFAULT true,
    allowed_claims TEXT[] DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ,

    UNIQUE(tenant_id, provider_id)
);

-- Federation sessions table
CREATE TABLE IF NOT EXISTS federation_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    provider_id UUID NOT NULL REFERENCES federated_providers(id) ON DELETE CASCADE,
    state VARCHAR(255) NOT NULL,
    nonce VARCHAR(255),
    pkce_verifier VARCHAR(255),
    redirect_uri TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
);

-- Linked identities table (accounts linked to federated identities)
CREATE TABLE IF NOT EXISTS linked_identities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    provider_id UUID NOT NULL REFERENCES federated_providers(id) ON DELETE CASCADE,
    external_id VARCHAR(255) NOT NULL,
    external_email VARCHAR(255),
    metadata JSONB DEFAULT '{}',
    linked_at TIMESTAMPTZ DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,

    UNIQUE(tenant_id, provider_id, external_id)
);

-- Broker sessions table (for OAuth2/OIDC broker flow)
CREATE TABLE IF NOT EXISTS broker_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    federation_session_id UUID REFERENCES federation_sessions(id) ON DELETE SET NULL,
    provider_id UUID REFERENCES federated_providers(id) ON DELETE SET NULL,
    external_id VARCHAR(255),
    claims JSONB DEFAULT '{}',
    code VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_federated_providers_tenant ON federated_providers(tenant_id);
CREATE INDEX IF NOT EXISTS idx_federated_providers_org ON federated_providers(organization_id);
CREATE INDEX IF NOT EXISTS idx_federated_providers_type ON federated_providers(provider_type);
CREATE INDEX IF NOT EXISTS idx_realm_mappings_tenant ON realm_mappings(tenant_id);
CREATE INDEX IF NOT EXISTS idx_realm_mappings_domain ON realm_mappings(domain);
CREATE INDEX IF NOT EXISTS idx_realm_mappings_provider ON realm_mappings(provider_id);
CREATE INDEX IF NOT EXISTS idx_trust_relationships_tenant ON trust_relationships(tenant_id);
CREATE INDEX IF NOT EXISTS idx_trust_relationships_provider ON trust_relationships(provider_id);
CREATE INDEX IF NOT EXISTS idx_federation_sessions_state ON federation_sessions(state);
CREATE INDEX IF NOT EXISTS idx_federation_sessions_expires ON federation_sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_linked_identities_user ON linked_identities(user_id);
CREATE INDEX IF NOT EXISTS idx_linked_identities_provider ON linked_identities(provider_id);
CREATE INDEX IF NOT EXISTS idx_linked_identities_external ON linked_identities(tenant_id, provider_id, external_id);
CREATE INDEX IF NOT EXISTS idx_broker_sessions_code ON broker_sessions(code);
CREATE INDEX IF NOT EXISTS idx_broker_sessions_expires ON broker_sessions(expires_at);

-- Enable RLS
ALTER TABLE federated_providers ENABLE ROW LEVEL SECURITY;
ALTER TABLE realm_mappings ENABLE ROW LEVEL SECURITY;
ALTER TABLE trust_relationships ENABLE ROW LEVEL SECURITY;
ALTER TABLE federation_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE linked_identities ENABLE ROW LEVEL SECURITY;
ALTER TABLE broker_sessions ENABLE ROW LEVEL SECURITY;

-- Force RLS
ALTER TABLE federated_providers FORCE ROW LEVEL SECURITY;
ALTER TABLE realm_mappings FORCE ROW LEVEL SECURITY;
ALTER TABLE trust_relationships FORCE ROW LEVEL SECURITY;
ALTER TABLE federation_sessions FORCE ROW LEVEL SECURITY;
ALTER TABLE linked_identities FORCE ROW LEVEL SECURITY;
ALTER TABLE broker_sessions FORCE ROW LEVEL SECURITY;

-- RLS Policies for federated_providers
DROP POLICY IF EXISTS federated_providers_select ON federated_providers;
CREATE POLICY federated_providers_select ON federated_providers
    FOR SELECT TO vault_app
    USING (
        tenant_id = current_tenant_id()
        AND (is_admin() OR (organization_id IS NULL OR is_org_member(organization_id)))
    );

DROP POLICY IF EXISTS federated_providers_write ON federated_providers;
CREATE POLICY federated_providers_write ON federated_providers
    FOR INSERT, UPDATE, DELETE TO vault_app
    USING (
        tenant_id = current_tenant_id()
        AND (is_admin() OR (organization_id IS NOT NULL AND is_org_admin(organization_id)))
    )
    WITH CHECK (tenant_id = current_tenant_id());

-- RLS Policies for realm_mappings
DROP POLICY IF EXISTS realm_mappings_select ON realm_mappings;
CREATE POLICY realm_mappings_select ON realm_mappings
    FOR SELECT TO vault_app
    USING (tenant_id = current_tenant_id());

DROP POLICY IF EXISTS realm_mappings_write ON realm_mappings;
CREATE POLICY realm_mappings_write ON realm_mappings
    FOR INSERT, UPDATE, DELETE TO vault_app
    USING (tenant_id = current_tenant_id() AND is_admin())
    WITH CHECK (tenant_id = current_tenant_id());

-- RLS Policies for trust_relationships
DROP POLICY IF EXISTS trust_relationships_select ON trust_relationships;
CREATE POLICY trust_relationships_select ON trust_relationships
    FOR SELECT TO vault_app
    USING (tenant_id = current_tenant_id());

DROP POLICY IF EXISTS trust_relationships_write ON trust_relationships;
CREATE POLICY trust_relationships_write ON trust_relationships
    FOR INSERT, UPDATE, DELETE TO vault_app
    USING (tenant_id = current_tenant_id() AND is_admin())
    WITH CHECK (tenant_id = current_tenant_id());

-- RLS Policies for federation_sessions
DROP POLICY IF EXISTS federation_sessions_select ON federation_sessions;
CREATE POLICY federation_sessions_select ON federation_sessions
    FOR SELECT TO vault_app
    USING (tenant_id = current_tenant_id());

DROP POLICY IF EXISTS federation_sessions_write ON federation_sessions;
CREATE POLICY federation_sessions_write ON federation_sessions
    FOR INSERT, UPDATE, DELETE TO vault_app
    USING (tenant_id = current_tenant_id())
    WITH CHECK (tenant_id = current_tenant_id());

-- RLS Policies for linked_identities
DROP POLICY IF EXISTS linked_identities_select ON linked_identities;
CREATE POLICY linked_identities_select ON linked_identities
    FOR SELECT TO vault_app
    USING (
        tenant_id = current_tenant_id()
        AND (is_admin() OR user_id = current_user_id())
    );

DROP POLICY IF EXISTS linked_identities_write ON linked_identities;
CREATE POLICY linked_identities_write ON linked_identities
    FOR INSERT, UPDATE, DELETE TO vault_app
    USING (tenant_id = current_tenant_id() AND is_admin())
    WITH CHECK (tenant_id = current_tenant_id());

-- RLS Policies for broker_sessions
DROP POLICY IF EXISTS broker_sessions_select ON broker_sessions;
CREATE POLICY broker_sessions_select ON broker_sessions
    FOR SELECT TO vault_app
    USING (tenant_id = current_tenant_id());

DROP POLICY IF EXISTS broker_sessions_write ON broker_sessions;
CREATE POLICY broker_sessions_write ON broker_sessions
    FOR INSERT, UPDATE, DELETE TO vault_app
    USING (tenant_id = current_tenant_id())
    WITH CHECK (tenant_id = current_tenant_id());

-- Helper function for domain discovery (bypasses RLS safely)
CREATE OR REPLACE FUNCTION get_federation_provider_by_domain(p_domain TEXT)
RETURNS TABLE (
    provider_id UUID,
    tenant_id UUID,
    provider_type federation_provider_type,
    config JSONB
) AS $$
BEGIN
    RETURN QUERY
    SELECT p.id, p.tenant_id, p.provider_type, p.config
    FROM realm_mappings rm
    JOIN federated_providers p ON p.id = rm.provider_id
    WHERE rm.domain = LOWER(p_domain)
      AND p.enabled = true;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public;

REVOKE ALL ON FUNCTION get_federation_provider_by_domain(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION get_federation_provider_by_domain(TEXT) TO vault_app;

-- Trigger for updated_at
CREATE OR REPLACE FUNCTION update_federation_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_federated_providers_updated_at
    BEFORE UPDATE ON federated_providers
    FOR EACH ROW EXECUTE FUNCTION update_federation_updated_at_column();

CREATE TRIGGER update_trust_relationships_updated_at
    BEFORE UPDATE ON trust_relationships
    FOR EACH ROW EXECUTE FUNCTION update_federation_updated_at_column();

-- Grants
GRANT SELECT, INSERT, UPDATE, DELETE ON federated_providers TO vault_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON realm_mappings TO vault_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON trust_relationships TO vault_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON federation_sessions TO vault_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON linked_identities TO vault_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON broker_sessions TO vault_app;

GRANT SELECT ON federated_providers TO vault_readonly;
GRANT SELECT ON realm_mappings TO vault_readonly;
GRANT SELECT ON trust_relationships TO vault_readonly;
GRANT SELECT ON federation_sessions TO vault_readonly;
GRANT SELECT ON linked_identities TO vault_readonly;
GRANT SELECT ON broker_sessions TO vault_readonly;
