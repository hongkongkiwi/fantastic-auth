-- Session binding migration
-- Adds fields to track and enforce session binding to IP and device

-- Add session binding columns to sessions table
ALTER TABLE sessions 
    ADD COLUMN IF NOT EXISTS created_ip INET,
    ADD COLUMN IF NOT EXISTS created_device_hash VARCHAR(64),
    ADD COLUMN IF NOT EXISTS bind_to_ip BOOLEAN DEFAULT false,
    ADD COLUMN IF NOT EXISTS bind_to_device BOOLEAN DEFAULT false,
    ADD COLUMN IF NOT EXISTS binding_violation_count INTEGER DEFAULT 0;

-- Add session binding settings to user_settings table
ALTER TABLE user_settings 
    ADD COLUMN IF NOT EXISTS require_email_verification_new_device BOOLEAN DEFAULT false,
    ADD COLUMN IF NOT EXISTS allow_single_session_per_device BOOLEAN DEFAULT false,
    ADD COLUMN IF NOT EXISTS session_binding_level VARCHAR(20) DEFAULT 'none';

-- Add session binding settings to organizations table (admin-enforced policies)
ALTER TABLE organizations 
    ADD COLUMN IF NOT EXISTS enforce_session_binding BOOLEAN DEFAULT false,
    ADD COLUMN IF NOT EXISTS session_binding_level VARCHAR(20) DEFAULT 'none',
    ADD COLUMN IF NOT EXISTS notify_on_new_device BOOLEAN DEFAULT true;

-- Create table for tracking device fingerprints for anomaly detection
CREATE TABLE IF NOT EXISTS user_known_devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    user_id UUID NOT NULL,
    device_fingerprint VARCHAR(64) NOT NULL,
    device_name VARCHAR(255),
    device_type VARCHAR(50),
    browser VARCHAR(100),
    os VARCHAR(100),
    ip_address INET,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_trusted BOOLEAN DEFAULT false,
    is_blocked BOOLEAN DEFAULT false,
    verified_at TIMESTAMPTZ,
    verification_token VARCHAR(128),
    verification_expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, user_id, device_fingerprint)
);

-- Create index for efficient device lookups
CREATE INDEX IF NOT EXISTS idx_user_known_devices_lookup 
    ON user_known_devices(tenant_id, user_id, device_fingerprint);
CREATE INDEX IF NOT EXISTS idx_user_known_devices_user 
    ON user_known_devices(tenant_id, user_id);
CREATE INDEX IF NOT EXISTS idx_user_known_devices_blocked 
    ON user_known_devices(tenant_id, user_id, is_blocked) 
    WHERE is_blocked = true;

-- Create table for session binding violation events
CREATE TABLE IF NOT EXISTS session_binding_violations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    session_id UUID NOT NULL,
    user_id UUID NOT NULL,
    violation_type VARCHAR(50) NOT NULL, -- 'ip_mismatch', 'device_mismatch', 'both'
    expected_ip INET,
    actual_ip INET,
    expected_device_hash VARCHAR(64),
    actual_device_hash VARCHAR(64),
    action_taken VARCHAR(50) NOT NULL, -- 'blocked', 'logged', 'notified'
    user_agent TEXT,
    request_details JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Create indexes for violation queries
CREATE INDEX IF NOT EXISTS idx_binding_violations_session 
    ON session_binding_violations(session_id);
CREATE INDEX IF NOT EXISTS idx_binding_violations_user 
    ON session_binding_violations(tenant_id, user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_binding_violations_recent 
    ON session_binding_violations(created_at DESC);

-- Enable RLS on new tables
ALTER TABLE user_known_devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE session_binding_violations ENABLE ROW LEVEL SECURITY;

-- RLS policies for user_known_devices
CREATE POLICY user_known_devices_tenant_isolation ON user_known_devices
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id')::UUID);

CREATE POLICY user_known_devices_user_view ON user_known_devices
    FOR SELECT
    USING (
        tenant_id = current_setting('app.current_tenant_id')::UUID
        AND user_id = current_setting('app.current_user_id')::UUID
    );

-- RLS policies for session_binding_violations
CREATE POLICY session_binding_violations_tenant_isolation ON session_binding_violations
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id')::UUID);

CREATE POLICY session_binding_violations_user_view ON session_binding_violations
    FOR SELECT
    USING (
        tenant_id = current_setting('app.current_tenant_id')::UUID
        AND user_id = current_setting('app.current_user_id')::UUID
    );

-- Grant access to vault_app role
GRANT ALL ON user_known_devices TO vault_app;
GRANT ALL ON session_binding_violations TO vault_app;
GRANT USAGE ON SEQUENCE user_known_devices_id_seq TO vault_app;
GRANT USAGE ON SEQUENCE session_binding_violations_id_seq TO vault_app;

-- Update comment on sessions table
COMMENT ON COLUMN sessions.created_ip IS 'IP address when session was created (for binding)';
COMMENT ON COLUMN sessions.created_device_hash IS 'Device fingerprint when session was created (for binding)';
COMMENT ON COLUMN sessions.bind_to_ip IS 'Whether to enforce IP binding for this session';
COMMENT ON COLUMN sessions.bind_to_device IS 'Whether to enforce device binding for this session';
COMMENT ON COLUMN sessions.binding_violation_count IS 'Number of binding violations detected for this session';
