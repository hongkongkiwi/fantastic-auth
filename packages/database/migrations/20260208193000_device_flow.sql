-- OAuth 2.0 Device Authorization Grant

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'device_code_status') THEN
        CREATE TYPE device_code_status AS ENUM ('pending', 'approved', 'denied', 'consumed', 'expired');
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS oauth_device_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id VARCHAR(255) NOT NULL,
    device_code VARCHAR(128) NOT NULL UNIQUE,
    user_code VARCHAR(32) NOT NULL,
    verification_uri TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    interval_seconds INTEGER NOT NULL DEFAULT 5,
    status device_code_status NOT NULL DEFAULT 'pending',
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    approved_at TIMESTAMPTZ,
    denied_at TIMESTAMPTZ,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE(tenant_id, user_code)
);

CREATE INDEX IF NOT EXISTS idx_device_codes_tenant ON oauth_device_codes(tenant_id);
CREATE INDEX IF NOT EXISTS idx_device_codes_status ON oauth_device_codes(status);
CREATE INDEX IF NOT EXISTS idx_device_codes_expires ON oauth_device_codes(expires_at);

ALTER TABLE oauth_device_codes ENABLE ROW LEVEL SECURITY;
ALTER TABLE oauth_device_codes FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS oauth_device_codes_select ON oauth_device_codes;
CREATE POLICY oauth_device_codes_select ON oauth_device_codes
    FOR SELECT TO vault_app
    USING (tenant_id = current_tenant_id());

DROP POLICY IF EXISTS oauth_device_codes_write ON oauth_device_codes;
CREATE POLICY oauth_device_codes_write ON oauth_device_codes
    FOR INSERT, UPDATE, DELETE TO vault_app
    USING (tenant_id = current_tenant_id())
    WITH CHECK (tenant_id = current_tenant_id());

GRANT SELECT, INSERT, UPDATE, DELETE ON oauth_device_codes TO vault_app;
GRANT SELECT ON oauth_device_codes TO vault_readonly;
