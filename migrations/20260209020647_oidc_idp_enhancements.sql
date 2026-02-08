-- OIDC Identity Provider Enhancements
-- 
-- This migration adds additional tables and fields for the complete OIDC IdP implementation:
-- - Custom scopes per tenant
-- - OAuth client metadata (description, URIs, etc.)
-- - Client usage tracking
-- - Device authorization codes (for device flow)
-- - Refresh token rotation tracking

-- =============================
-- OAuth Client Enhancements
-- =============================

-- Add metadata fields to oauth_clients if they don't exist
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'oauth_clients' AND column_name = 'description') THEN
        ALTER TABLE oauth_clients ADD COLUMN description TEXT;
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'oauth_clients' AND column_name = 'client_uri') THEN
        ALTER TABLE oauth_clients ADD COLUMN client_uri TEXT;
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'oauth_clients' AND column_name = 'logo_uri') THEN
        ALTER TABLE oauth_clients ADD COLUMN logo_uri TEXT;
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'oauth_clients' AND column_name = 'policy_uri') THEN
        ALTER TABLE oauth_clients ADD COLUMN policy_uri TEXT;
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'oauth_clients' AND column_name = 'tos_uri') THEN
        ALTER TABLE oauth_clients ADD COLUMN tos_uri TEXT;
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'oauth_clients' AND column_name = 'contacts') THEN
        ALTER TABLE oauth_clients ADD COLUMN contacts JSONB DEFAULT '[]';
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'oauth_clients' AND column_name = 'is_active') THEN
        ALTER TABLE oauth_clients ADD COLUMN is_active BOOLEAN NOT NULL DEFAULT true;
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'oauth_clients' AND column_name = 'allowed_grants') THEN
        ALTER TABLE oauth_clients ADD COLUMN allowed_grants JSONB DEFAULT '["authorization_code", "refresh_token"]';
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'oauth_clients' AND column_name = 'pkce_s256_required') THEN
        ALTER TABLE oauth_clients ADD COLUMN pkce_s256_required BOOLEAN NOT NULL DEFAULT true;
    END IF;
END $$;

-- =============================
-- Custom Scopes (per tenant)
-- =============================
CREATE TABLE IF NOT EXISTS oauth_scopes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    claims JSONB NOT NULL DEFAULT '[]',
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, name)
);

-- Insert default scopes for all tenants
INSERT INTO oauth_scopes (tenant_id, name, description, claims)
SELECT 
    t.id as tenant_id,
    s.name,
    s.description,
    s.claims
FROM tenants t
CROSS JOIN (
    VALUES 
        ('openid', 'Signals that the request is an OpenID Connect request', '["sub"]'),
        ('profile', 'Access to the user''s basic profile information', '["name", "family_name", "given_name", "middle_name", "nickname", "preferred_username", "profile", "picture", "website", "gender", "birthdate", "zoneinfo", "locale", "updated_at"]'),
        ('email', 'Access to the user''s email address', '["email", "email_verified"]'),
        ('phone', 'Access to the user''s phone number', '["phone_number", "phone_number_verified"]'),
        ('address', 'Access to the user''s postal address', '["address"]'),
        ('offline_access', 'Request a refresh token for offline access', '[]')
) AS s(name, description, claims)
ON CONFLICT (tenant_id, name) DO NOTHING;

CREATE INDEX IF NOT EXISTS idx_oauth_scopes_tenant ON oauth_scopes(tenant_id);
CREATE INDEX IF NOT EXISTS idx_oauth_scopes_name ON oauth_scopes(name);

ALTER TABLE oauth_scopes ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS oauth_scopes_isolation ON oauth_scopes;
CREATE POLICY oauth_scopes_isolation ON oauth_scopes
    FOR ALL
    TO vault_app
    USING (tenant_id = current_tenant_id());

-- =============================
-- Device Authorization Codes (RFC 8628)
-- =============================
CREATE TABLE IF NOT EXISTS oauth_device_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    device_code VARCHAR(255) NOT NULL UNIQUE,
    user_code VARCHAR(20) NOT NULL,
    client_id VARCHAR(255) NOT NULL,
    scope TEXT,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    interval_seconds INTEGER NOT NULL DEFAULT 5,
    last_poll_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_device_codes_tenant ON oauth_device_codes(tenant_id);
CREATE INDEX IF NOT EXISTS idx_device_codes_code ON oauth_device_codes(device_code);
CREATE INDEX IF NOT EXISTS idx_device_codes_user_code ON oauth_device_codes(user_code);
CREATE INDEX IF NOT EXISTS idx_device_codes_status ON oauth_device_codes(status);

ALTER TABLE oauth_device_codes ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS oauth_device_codes_isolation ON oauth_device_codes;
CREATE POLICY oauth_device_codes_isolation ON oauth_device_codes
    FOR ALL
    TO vault_app
    USING (tenant_id = current_tenant_id());

-- =============================
-- Refresh Token Tracking (for rotation)
-- =============================
CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id VARCHAR(255) NOT NULL,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL,
    parent_token_hash TEXT,
    scope TEXT,
    access_token_jti VARCHAR(255),
    is_rotated BOOLEAN NOT NULL DEFAULT false,
    revoked_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_tenant ON oauth_refresh_tokens(tenant_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_hash ON oauth_refresh_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_parent ON oauth_refresh_tokens(parent_token_hash);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_access_jti ON oauth_refresh_tokens(access_token_jti);

ALTER TABLE oauth_refresh_tokens ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS oauth_refresh_tokens_isolation ON oauth_refresh_tokens;
CREATE POLICY oauth_refresh_tokens_isolation ON oauth_refresh_tokens
    FOR ALL
    TO vault_app
    USING (tenant_id = current_tenant_id());

-- =============================
-- Client Usage Statistics
-- =============================
CREATE TABLE IF NOT EXISTS oauth_client_usage (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id VARCHAR(255) NOT NULL,
    authorization_requests BIGINT NOT NULL DEFAULT 0,
    token_requests BIGINT NOT NULL DEFAULT 0,
    active_tokens BIGINT NOT NULL DEFAULT 0,
    active_refresh_tokens BIGINT NOT NULL DEFAULT 0,
    last_used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, client_id)
);

CREATE INDEX IF NOT EXISTS idx_client_usage_tenant ON oauth_client_usage(tenant_id);
CREATE INDEX IF NOT EXISTS idx_client_usage_client ON oauth_client_usage(client_id);
CREATE INDEX IF NOT EXISTS idx_client_usage_last_used ON oauth_client_usage(last_used_at);

ALTER TABLE oauth_client_usage ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS oauth_client_usage_isolation ON oauth_client_usage;
CREATE POLICY oauth_client_usage_isolation ON oauth_client_usage
    FOR ALL
    TO vault_app
    USING (tenant_id = current_tenant_id());

-- =============================
-- Consent Records (user approval for client access)
-- =============================
CREATE TABLE IF NOT EXISTS oauth_consents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id VARCHAR(255) NOT NULL,
    scope TEXT NOT NULL,
    claims JSONB DEFAULT '{}',
    is_remembered BOOLEAN NOT NULL DEFAULT false,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, user_id, client_id)
);

CREATE INDEX IF NOT EXISTS idx_oauth_consents_tenant ON oauth_consents(tenant_id);
CREATE INDEX IF NOT EXISTS idx_oauth_consents_user ON oauth_consents(user_id);
CREATE INDEX IF NOT EXISTS idx_oauth_consents_client ON oauth_consents(client_id);

ALTER TABLE oauth_consents ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS oauth_consents_isolation ON oauth_consents;
CREATE POLICY oauth_consents_isolation ON oauth_consents
    FOR ALL
    TO vault_app
    USING (tenant_id = current_tenant_id());

-- =============================
-- Functions for updating timestamps
-- =============================
CREATE OR REPLACE FUNCTION update_oauth_scopes_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_oauth_scopes_updated_at ON oauth_scopes;
CREATE TRIGGER trigger_oauth_scopes_updated_at
    BEFORE UPDATE ON oauth_scopes
    FOR EACH ROW
    EXECUTE FUNCTION update_oauth_scopes_updated_at();

CREATE OR REPLACE FUNCTION update_oauth_client_usage_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_oauth_client_usage_updated_at ON oauth_client_usage;
CREATE TRIGGER trigger_oauth_client_usage_updated_at
    BEFORE UPDATE ON oauth_client_usage
    FOR EACH ROW
    EXECUTE FUNCTION update_oauth_client_usage_updated_at();

CREATE OR REPLACE FUNCTION update_oauth_consents_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_oauth_consents_updated_at ON oauth_consents;
CREATE TRIGGER trigger_oauth_consents_updated_at
    BEFORE UPDATE ON oauth_consents
    FOR EACH ROW
    EXECUTE FUNCTION update_oauth_consents_updated_at();

-- =============================
-- Comments
-- =============================
COMMENT ON TABLE oauth_scopes IS 'Custom OAuth/OIDC scopes defined per tenant';
COMMENT ON TABLE oauth_device_codes IS 'Device authorization codes for OAuth 2.0 Device Flow (RFC 8628)';
COMMENT ON TABLE oauth_refresh_tokens IS 'Refresh tokens with rotation tracking';
COMMENT ON TABLE oauth_client_usage IS 'Usage statistics for OAuth clients';
COMMENT ON TABLE oauth_consents IS 'User consent records for OAuth client access';
