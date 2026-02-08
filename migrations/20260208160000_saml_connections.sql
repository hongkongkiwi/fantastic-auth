-- SAML 2.0 Connections for Enterprise SSO
-- Supports Service Provider and Identity Provider configurations

-- Enable UUID extension if not already enabled
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- SAML connection status enum
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'saml_connection_status') THEN
        CREATE TYPE saml_connection_status AS ENUM ('active', 'inactive', 'error');
    END IF;
END $$;

-- SAML connections table
CREATE TABLE IF NOT EXISTS saml_connections (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    
    -- Identity Provider Configuration
    idp_entity_id VARCHAR(500),
    idp_sso_url VARCHAR(500),
    idp_slo_url VARCHAR(500),
    idp_certificate TEXT, -- PEM format X509 certificate
    
    -- Service Provider Configuration
    sp_entity_id VARCHAR(500) NOT NULL,
    sp_acs_url VARCHAR(500) NOT NULL,
    sp_slo_url VARCHAR(500),
    sp_certificate TEXT, -- PEM format X509 certificate
    sp_private_key TEXT, -- PEM format private key (encrypted at application level)
    
    -- SAML Settings
    name_id_format VARCHAR(100) NOT NULL DEFAULT 'email_address',
    want_authn_requests_signed BOOLEAN NOT NULL DEFAULT false,
    want_assertions_signed BOOLEAN NOT NULL DEFAULT true,
    want_assertions_encrypted BOOLEAN NOT NULL DEFAULT false,
    
    -- Attribute Mappings (JSONB for flexibility)
    attribute_mappings JSONB NOT NULL DEFAULT '{
        "email": "email",
        "firstName": "profile.first_name",
        "lastName": "profile.last_name",
        "displayName": "profile.name"
    }',
    
    -- JIT Provisioning
    jit_provisioning_enabled BOOLEAN NOT NULL DEFAULT true,
    jit_default_role VARCHAR(50) DEFAULT 'member',
    jit_group_mappings JSONB DEFAULT '{}',
    
    -- Status
    status saml_connection_status NOT NULL DEFAULT 'active',
    last_error TEXT,
    last_tested_at TIMESTAMPTZ,
    
    -- Metadata timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- Constraints
    UNIQUE(tenant_id, name),
    CHECK (idp_sso_url IS NULL OR idp_sso_url LIKE 'http%'),
    CHECK (idp_slo_url IS NULL OR idp_slo_url LIKE 'http%')
);

-- SAML request/response tracking for replay prevention
CREATE TABLE IF NOT EXISTS saml_message_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    connection_id UUID REFERENCES saml_connections(id) ON DELETE CASCADE,
    message_id VARCHAR(255) NOT NULL,
    message_type VARCHAR(50) NOT NULL, -- 'authn_request', 'response', 'logout_request', 'logout_response'
    issuer VARCHAR(500),
    destination VARCHAR(500),
    status VARCHAR(50),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    UNIQUE(tenant_id, message_id)
);

-- SAML user mappings (for linking SAML NameID to internal users)
CREATE TABLE IF NOT EXISTS saml_user_mappings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    connection_id UUID NOT NULL REFERENCES saml_connections(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name_id VARCHAR(500) NOT NULL,
    name_id_format VARCHAR(100),
    session_index VARCHAR(255),
    last_login_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    UNIQUE(tenant_id, connection_id, name_id),
    UNIQUE(tenant_id, user_id, connection_id)
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_saml_connections_tenant ON saml_connections(tenant_id);
CREATE INDEX IF NOT EXISTS idx_saml_connections_status ON saml_connections(status);

CREATE INDEX IF NOT EXISTS idx_saml_message_log_tenant ON saml_message_log(tenant_id);
CREATE INDEX IF NOT EXISTS idx_saml_message_log_message_id ON saml_message_log(message_id);
CREATE INDEX IF NOT EXISTS idx_saml_message_log_created ON saml_message_log(created_at);

CREATE INDEX IF NOT EXISTS idx_saml_user_mappings_tenant ON saml_user_mappings(tenant_id);
CREATE INDEX IF NOT EXISTS idx_saml_user_mappings_connection ON saml_user_mappings(connection_id);
CREATE INDEX IF NOT EXISTS idx_saml_user_mappings_user ON saml_user_mappings(user_id);
CREATE INDEX IF NOT EXISTS idx_saml_user_mappings_name_id ON saml_user_mappings(name_id);

-- Row Level Security policies
ALTER TABLE saml_connections ENABLE ROW LEVEL SECURITY;
ALTER TABLE saml_message_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE saml_user_mappings ENABLE ROW LEVEL SECURITY;

-- Drop existing policies if they exist
DROP POLICY IF EXISTS saml_connections_isolation ON saml_connections;
DROP POLICY IF EXISTS saml_message_log_isolation ON saml_message_log;
DROP POLICY IF EXISTS saml_user_mappings_isolation ON saml_user_mappings;

-- Create RLS policies
CREATE POLICY saml_connections_isolation ON saml_connections
    FOR ALL
    TO vault_app
    USING (tenant_id = current_tenant_id());

CREATE POLICY saml_message_log_isolation ON saml_message_log
    FOR ALL
    TO vault_app
    USING (tenant_id = current_tenant_id());

CREATE POLICY saml_user_mappings_isolation ON saml_user_mappings
    FOR ALL
    TO vault_app
    USING (tenant_id = current_tenant_id());

-- Cleanup function for old SAML message logs
CREATE OR REPLACE FUNCTION cleanup_saml_message_log()
RETURNS void AS $$
BEGIN
    DELETE FROM saml_message_log
    WHERE created_at < NOW() - INTERVAL '24 hours';
END;
$$ LANGUAGE plpgsql;

-- Trigger to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_saml_connections_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_saml_connections_updated_at ON saml_connections;
CREATE TRIGGER trigger_saml_connections_updated_at
    BEFORE UPDATE ON saml_connections
    FOR EACH ROW
    EXECUTE FUNCTION update_saml_connections_updated_at();

-- Comments for documentation
COMMENT ON TABLE saml_connections IS 'Stores SAML 2.0 IdP and SP configuration for SSO';
COMMENT ON TABLE saml_message_log IS 'Tracks SAML messages for replay prevention and audit';
COMMENT ON TABLE saml_user_mappings IS 'Maps SAML NameIDs to internal user accounts';
