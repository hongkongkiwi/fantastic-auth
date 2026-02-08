-- Push Notification MFA Tables
-- Supports FCM (Firebase Cloud Messaging) and APNS (Apple Push Notification Service)

-- ============================================
-- Enums
-- ============================================
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'push_device_type') THEN
        CREATE TYPE push_device_type AS ENUM ('ios', 'android');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'push_request_status') THEN
        CREATE TYPE push_request_status AS ENUM ('pending', 'approved', 'denied', 'expired');
    END IF;
END $$;

-- ============================================
-- Push Devices Table
-- ============================================
CREATE TABLE IF NOT EXISTS push_devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    device_type push_device_type NOT NULL,
    device_name VARCHAR(255),
    device_token TEXT NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    public_key TEXT, -- For verifying device responses
    
    UNIQUE(tenant_id, user_id, device_token)
);

-- Indexes for push devices
CREATE INDEX IF NOT EXISTS idx_push_devices_user ON push_devices(tenant_id, user_id);
CREATE INDEX IF NOT EXISTS idx_push_devices_active ON push_devices(tenant_id, user_id, is_active) WHERE is_active = TRUE;
CREATE INDEX IF NOT EXISTS idx_push_devices_token ON push_devices(device_token);

-- ============================================
-- Push Requests Table
-- ============================================
CREATE TABLE IF NOT EXISTS push_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    device_id UUID REFERENCES push_devices(id) ON DELETE SET NULL,
    session_id UUID REFERENCES sessions(id) ON DELETE SET NULL,
    status push_request_status NOT NULL DEFAULT 'pending',
    ip_address INET,
    user_agent TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    responded_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Response signature verification
    response_signature TEXT,
    response_timestamp TIMESTAMPTZ
);

-- Indexes for push requests
CREATE INDEX IF NOT EXISTS idx_push_requests_user ON push_requests(tenant_id, user_id);
CREATE INDEX IF NOT EXISTS idx_push_requests_status ON push_requests(tenant_id, user_id, status);
CREATE INDEX IF NOT EXISTS idx_push_requests_session ON push_requests(session_id);
CREATE INDEX IF NOT EXISTS idx_push_requests_expires ON push_requests(expires_at);
CREATE INDEX IF NOT EXISTS idx_push_requests_pending ON push_requests(status, expires_at) WHERE status = 'pending';

-- ============================================
-- Push MFA Settings (per tenant)
-- ============================================
CREATE TABLE IF NOT EXISTS push_mfa_settings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL UNIQUE REFERENCES tenants(id) ON DELETE CASCADE,
    -- FCM Configuration
    fcm_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    fcm_service_account_json_encrypted TEXT, -- Encrypted service account credentials
    -- APNS Configuration
    apns_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    apns_key_id VARCHAR(20),
    apns_team_id VARCHAR(20),
    apns_bundle_id VARCHAR(255),
    apns_private_key_encrypted TEXT, -- Encrypted private key
    apns_use_sandbox BOOLEAN NOT NULL DEFAULT FALSE,
    -- Request settings
    request_timeout_seconds INTEGER NOT NULL DEFAULT 300, -- 5 minutes default
    max_devices_per_user INTEGER NOT NULL DEFAULT 5,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_push_mfa_settings_tenant ON push_mfa_settings(tenant_id);

-- ============================================
-- RLS Policies
-- ============================================
ALTER TABLE push_devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE push_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE push_mfa_settings ENABLE ROW LEVEL SECURITY;

-- Force RLS for table owners
ALTER TABLE push_devices FORCE ROW LEVEL SECURITY;
ALTER TABLE push_requests FORCE ROW LEVEL SECURITY;
ALTER TABLE push_mfa_settings FORCE ROW LEVEL SECURITY;

-- Push devices policies
DROP POLICY IF EXISTS push_devices_select ON push_devices;
CREATE POLICY push_devices_select ON push_devices
    FOR SELECT TO vault_app
    USING (
        tenant_id = current_tenant_id()
        AND (user_id = current_user_id() OR is_admin())
    );

DROP POLICY IF EXISTS push_devices_insert ON push_devices;
CREATE POLICY push_devices_insert ON push_devices
    FOR INSERT TO vault_app
    WITH CHECK (
        tenant_id = current_tenant_id()
        AND user_id = current_user_id()
    );

DROP POLICY IF EXISTS push_devices_update ON push_devices;
CREATE POLICY push_devices_update ON push_devices
    FOR UPDATE TO vault_app
    USING (
        tenant_id = current_tenant_id()
        AND (user_id = current_user_id() OR is_admin())
    )
    WITH CHECK (tenant_id = current_tenant_id());

DROP POLICY IF EXISTS push_devices_delete ON push_devices;
CREATE POLICY push_devices_delete ON push_devices
    FOR DELETE TO vault_app
    USING (
        tenant_id = current_tenant_id()
        AND (user_id = current_user_id() OR is_admin())
    );

-- Push requests policies
DROP POLICY IF EXISTS push_requests_select ON push_requests;
CREATE POLICY push_requests_select ON push_requests
    FOR SELECT TO vault_app
    USING (
        tenant_id = current_tenant_id()
        AND (user_id = current_user_id() OR is_admin())
    );

DROP POLICY IF EXISTS push_requests_insert ON push_requests;
CREATE POLICY push_requests_insert ON push_requests
    FOR INSERT TO vault_app
    WITH CHECK (tenant_id = current_tenant_id());

DROP POLICY IF EXISTS push_requests_update ON push_requests;
CREATE POLICY push_requests_update ON push_requests
    FOR UPDATE TO vault_app
    USING (tenant_id = current_tenant_id())
    WITH CHECK (tenant_id = current_tenant_id());

-- Push MFA settings policies (admin only)
DROP POLICY IF EXISTS push_mfa_settings_select ON push_mfa_settings;
CREATE POLICY push_mfa_settings_select ON push_mfa_settings
    FOR SELECT TO vault_app
    USING (tenant_id = current_tenant_id() AND is_admin());

DROP POLICY IF EXISTS push_mfa_settings_write ON push_mfa_settings;
CREATE POLICY push_mfa_settings_write ON push_mfa_settings
    FOR INSERT, UPDATE, DELETE TO vault_app
    USING (tenant_id = current_tenant_id() AND is_admin())
    WITH CHECK (tenant_id = current_tenant_id());

-- ============================================
-- Triggers
-- ============================================
DROP TRIGGER IF EXISTS update_push_mfa_settings_updated_at ON push_mfa_settings;
CREATE TRIGGER update_push_mfa_settings_updated_at
    BEFORE UPDATE ON push_mfa_settings
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================
-- Comments
-- ============================================
COMMENT ON TABLE push_devices IS 'Registered devices for push notification MFA';
COMMENT ON TABLE push_requests IS 'Push MFA authentication requests';
COMMENT ON TABLE push_mfa_settings IS 'Tenant-specific push MFA configuration';
COMMENT ON COLUMN push_devices.device_token IS 'FCM or APNS device token';
COMMENT ON COLUMN push_devices.public_key IS 'Ed25519 public key for verifying device responses';
COMMENT ON COLUMN push_requests.response_signature IS 'Cryptographic signature of the approve/deny response';

-- ============================================
-- Grants
-- ============================================
GRANT SELECT, INSERT, UPDATE, DELETE ON push_devices TO vault_app;
GRANT SELECT, INSERT, UPDATE ON push_requests TO vault_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON push_mfa_settings TO vault_app;

GRANT SELECT ON push_devices TO vault_readonly;
GRANT SELECT ON push_requests TO vault_readonly;
GRANT SELECT ON push_mfa_settings TO vault_readonly;
