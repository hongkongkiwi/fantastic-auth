-- M2M Authentication Migration
-- Machine-to-Machine authentication for services, APIs, and IoT devices

-- ============================================
-- Service Accounts Table
-- ============================================

CREATE TABLE service_accounts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    client_id VARCHAR(255) UNIQUE NOT NULL,
    client_secret_hash VARCHAR(255) NOT NULL,
    scopes TEXT[] DEFAULT '{}',
    permissions TEXT[] DEFAULT '{}',
    rate_limit_rps INTEGER,
    rate_limit_burst INTEGER,
    expires_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    is_active BOOLEAN DEFAULT true
);

-- Indexes for service accounts
CREATE INDEX idx_service_accounts_tenant ON service_accounts(tenant_id);
CREATE INDEX idx_service_accounts_client_id ON service_accounts(client_id);
CREATE INDEX idx_service_accounts_active ON service_accounts(tenant_id, is_active) WHERE is_active = true;
CREATE INDEX idx_service_accounts_expires ON service_accounts(expires_at) WHERE expires_at IS NOT NULL;

-- ============================================
-- API Keys Table
-- ============================================

CREATE TABLE api_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    service_account_id UUID NOT NULL REFERENCES service_accounts(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    key_hash VARCHAR(255) NOT NULL,
    name VARCHAR(255),
    scopes TEXT[],
    expires_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    is_active BOOLEAN DEFAULT true
);

-- Indexes for API keys
CREATE INDEX idx_api_keys_service_account ON api_keys(service_account_id);
CREATE INDEX idx_api_keys_tenant ON api_keys(tenant_id);
CREATE INDEX idx_api_keys_active ON api_keys(service_account_id, is_active) WHERE is_active = true;
CREATE INDEX idx_api_keys_expires ON api_keys(expires_at) WHERE expires_at IS NOT NULL;

-- ============================================
-- Row-Level Security Policies
-- ============================================

-- Enable RLS on M2M tables
ALTER TABLE service_accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;

-- Service accounts policy: tenant isolation
CREATE POLICY tenant_isolation_service_accounts ON service_accounts
    FOR ALL
    TO vault_app
    USING (tenant_id = current_tenant_id());

-- API keys policy: tenant isolation
CREATE POLICY tenant_isolation_api_keys ON api_keys
    FOR ALL
    TO vault_app
    USING (tenant_id = current_tenant_id());

-- ============================================
-- M2M Audit Log Actions
-- ============================================

-- Note: These use the existing audit_logs table with custom action types
-- Actions include:
-- - m2m.auth_success: Successful M2M authentication
-- - m2m.auth_failed: Failed M2M authentication
-- - m2m.token_issued: Access token issued
-- - m2m.token_failed: Token request failed
-- - m2m.rate_limit_exceeded: Rate limit hit
-- - service_account.created: Service account created
-- - service_account.updated: Service account updated
-- - service_account.deleted: Service account deleted
-- - service_account.secret_rotated: Client secret rotated
-- - service_account.api_key_created: API key created
-- - service_account.api_key_revoked: API key revoked
-- - service_account.all_keys_revoked: All API keys revoked

-- ============================================
-- Comments
-- ============================================

COMMENT ON TABLE service_accounts IS 'Service accounts for M2M authentication with client credentials flow';
COMMENT ON COLUMN service_accounts.client_secret_hash IS 'Argon2 hash of the client secret - only shown once on creation';
COMMENT ON COLUMN service_accounts.scopes IS 'OAuth scopes assigned to this service account';
COMMENT ON COLUMN service_accounts.permissions IS 'Internal permissions for authorization decisions';
COMMENT ON COLUMN service_accounts.rate_limit_rps IS 'Rate limit: requests per second';
COMMENT ON COLUMN service_accounts.rate_limit_burst IS 'Rate limit: burst capacity';

COMMENT ON TABLE api_keys IS 'API keys for M2M authentication - alternative to client credentials';
COMMENT ON COLUMN api_keys.key_hash IS 'Argon2 hash of the API key - only the unhashed key is shown once on creation';
COMMENT ON COLUMN api_keys.scopes IS 'Optional scope override for this specific key';
COMMENT ON COLUMN api_keys.service_account_id IS 'Reference to the parent service account';
