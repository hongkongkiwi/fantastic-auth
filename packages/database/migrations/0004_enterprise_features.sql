-- Enterprise features: SSO, SCIM, MFA devices, branding, roles, audit exports

-- SSO connections and domains
CREATE TABLE IF NOT EXISTS sso_connections (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    type sso_provider_type NOT NULL,
    name VARCHAR(255) NOT NULL,
    config JSONB NOT NULL DEFAULT '{}',
    status VARCHAR(50) NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS sso_domains (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    connection_id UUID NOT NULL REFERENCES sso_connections(id) ON DELETE CASCADE,
    domain VARCHAR(255) NOT NULL,
    verification_token VARCHAR(255) NOT NULL,
    verified_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, domain)
);

CREATE TABLE IF NOT EXISTS org_sso_settings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    connection_id UUID REFERENCES sso_connections(id) ON DELETE SET NULL,
    required BOOLEAN NOT NULL DEFAULT FALSE,
    jit_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    default_role org_role NOT NULL DEFAULT 'member',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(organization_id)
);

-- Organization domains and roles
CREATE TABLE IF NOT EXISTS organization_domains (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    domain VARCHAR(255) NOT NULL,
    verification_token VARCHAR(255) NOT NULL,
    verified_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(organization_id, domain)
);

CREATE TABLE IF NOT EXISTS organization_roles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    permissions JSONB NOT NULL DEFAULT '[]',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(organization_id, name)
);

-- Branding and themes
CREATE TABLE IF NOT EXISTS tenant_branding (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    branding JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id)
);

CREATE TABLE IF NOT EXISTS tenant_themes (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    theme JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id)
);

-- MFA devices and backup codes
CREATE TABLE IF NOT EXISTS mfa_credentials (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    method mfa_method NOT NULL,
    credential_id VARCHAR(255),
    public_key TEXT,
    metadata JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS mfa_backup_codes (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash VARCHAR(255) NOT NULL,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- SCIM provisioning
CREATE TABLE IF NOT EXISTS scim_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS scim_mappings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    resource_type VARCHAR(50) NOT NULL,
    external_id VARCHAR(255) NOT NULL,
    local_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, resource_type, external_id)
);

CREATE TABLE IF NOT EXISTS scim_users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_name VARCHAR(255) NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    external_id VARCHAR(255),
    data JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, user_name)
);

CREATE TABLE IF NOT EXISTS scim_groups (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    display_name VARCHAR(255) NOT NULL,
    data JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, display_name)
);

-- Audit exports and streaming
CREATE TABLE IF NOT EXISTS audit_exports (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    format VARCHAR(10) NOT NULL DEFAULT 'json',
    status VARCHAR(50) NOT NULL DEFAULT 'queued',
    from_ts TIMESTAMPTZ NOT NULL,
    to_ts TIMESTAMPTZ NOT NULL,
    file_url TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS audit_webhooks (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    secret_hash VARCHAR(255) NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Directory connectors
CREATE TABLE IF NOT EXISTS directory_connections (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    type VARCHAR(50) NOT NULL DEFAULT 'ldap',
    name VARCHAR(255) NOT NULL,
    config JSONB NOT NULL DEFAULT '{}',
    status VARCHAR(50) NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Security policies (step-up and risk rules)
CREATE TABLE IF NOT EXISTS security_policies (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    conditions JSONB NOT NULL DEFAULT '{}',
    actions JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Enable RLS
ALTER TABLE sso_connections ENABLE ROW LEVEL SECURITY;
ALTER TABLE sso_domains ENABLE ROW LEVEL SECURITY;
ALTER TABLE org_sso_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE organization_domains ENABLE ROW LEVEL SECURITY;
ALTER TABLE organization_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_branding ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_themes ENABLE ROW LEVEL SECURITY;
ALTER TABLE mfa_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE mfa_backup_codes ENABLE ROW LEVEL SECURITY;
ALTER TABLE scim_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE scim_mappings ENABLE ROW LEVEL SECURITY;
ALTER TABLE scim_users ENABLE ROW LEVEL SECURITY;
ALTER TABLE scim_groups ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_exports ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_webhooks ENABLE ROW LEVEL SECURITY;
ALTER TABLE directory_connections ENABLE ROW LEVEL SECURITY;
ALTER TABLE security_policies ENABLE ROW LEVEL SECURITY;

-- RLS policies
CREATE POLICY tenant_isolation_sso_connections ON sso_connections
    FOR ALL TO vault_app
    USING (tenant_id = current_tenant_id());

CREATE POLICY tenant_isolation_sso_domains ON sso_domains
    FOR ALL TO vault_app
    USING (tenant_id = current_tenant_id());

CREATE POLICY tenant_isolation_org_sso_settings ON org_sso_settings
    FOR ALL TO vault_app
    USING (tenant_id = current_tenant_id());

CREATE POLICY tenant_isolation_org_domains ON organization_domains
    FOR ALL TO vault_app
    USING (tenant_id = current_tenant_id());

CREATE POLICY tenant_isolation_org_roles ON organization_roles
    FOR ALL TO vault_app
    USING (tenant_id = current_tenant_id());

CREATE POLICY tenant_isolation_branding ON tenant_branding
    FOR ALL TO vault_app
    USING (tenant_id = current_tenant_id());

CREATE POLICY tenant_isolation_themes ON tenant_themes
    FOR ALL TO vault_app
    USING (tenant_id = current_tenant_id());

CREATE POLICY tenant_isolation_mfa_credentials ON mfa_credentials
    FOR ALL TO vault_app
    USING (tenant_id = current_tenant_id());

CREATE POLICY tenant_isolation_mfa_backup_codes ON mfa_backup_codes
    FOR ALL TO vault_app
    USING (tenant_id = current_tenant_id());

CREATE POLICY tenant_isolation_scim_tokens ON scim_tokens
    FOR ALL TO vault_app
    USING (tenant_id = current_tenant_id());

CREATE POLICY tenant_isolation_scim_mappings ON scim_mappings
    FOR ALL TO vault_app
    USING (tenant_id = current_tenant_id());

CREATE POLICY tenant_isolation_scim_users ON scim_users
    FOR ALL TO vault_app
    USING (tenant_id = current_tenant_id());

CREATE POLICY tenant_isolation_scim_groups ON scim_groups
    FOR ALL TO vault_app
    USING (tenant_id = current_tenant_id());

CREATE POLICY tenant_isolation_audit_exports ON audit_exports
    FOR ALL TO vault_app
    USING (tenant_id = current_tenant_id());

CREATE POLICY tenant_isolation_audit_webhooks ON audit_webhooks
    FOR ALL TO vault_app
    USING (tenant_id = current_tenant_id());

CREATE POLICY tenant_isolation_directory_connections ON directory_connections
    FOR ALL TO vault_app
    USING (tenant_id = current_tenant_id());

CREATE POLICY tenant_isolation_security_policies ON security_policies
    FOR ALL TO vault_app
    USING (tenant_id = current_tenant_id());

-- Indexes
CREATE INDEX IF NOT EXISTS idx_sso_connections_tenant ON sso_connections(tenant_id);
CREATE INDEX IF NOT EXISTS idx_sso_domains_tenant ON sso_domains(tenant_id);
CREATE INDEX IF NOT EXISTS idx_org_domains_org ON organization_domains(organization_id);
CREATE INDEX IF NOT EXISTS idx_org_roles_org ON organization_roles(organization_id);
CREATE INDEX IF NOT EXISTS idx_mfa_credentials_user ON mfa_credentials(user_id);
CREATE INDEX IF NOT EXISTS idx_scim_mappings_tenant ON scim_mappings(tenant_id);
CREATE INDEX IF NOT EXISTS idx_scim_users_tenant ON scim_users(tenant_id);
CREATE INDEX IF NOT EXISTS idx_scim_groups_tenant ON scim_groups(tenant_id);
CREATE INDEX IF NOT EXISTS idx_audit_exports_tenant ON audit_exports(tenant_id);
CREATE INDEX IF NOT EXISTS idx_audit_webhooks_tenant ON audit_webhooks(tenant_id);
CREATE INDEX IF NOT EXISTS idx_directory_connections_tenant ON directory_connections(tenant_id);
CREATE INDEX IF NOT EXISTS idx_security_policies_tenant ON security_policies(tenant_id);
