-- Biometric authentication tables for Face ID, Touch ID, and fingerprint

-- Create biometric type enum
CREATE TYPE biometric_type AS ENUM ('face_id', 'touch_id', 'fingerprint', 'face_unlock', 'iris');

-- Biometric keys table
CREATE TABLE biometric_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    public_key BYTEA NOT NULL,
    key_id TEXT NOT NULL UNIQUE, -- Client-generated key ID
    device_name TEXT NOT NULL,
    biometric_type biometric_type NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_used_at TIMESTAMP WITH TIME ZONE,
    UNIQUE(user_id, key_id)
);

-- Biometric challenges table (for challenge-response authentication)
CREATE TABLE biometric_challenges (
    key_id TEXT PRIMARY KEY REFERENCES biometric_keys(key_id) ON DELETE CASCADE,
    challenge TEXT NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX idx_biometric_keys_user ON biometric_keys(user_id);
CREATE INDEX idx_biometric_keys_tenant ON biometric_keys(tenant_id);
CREATE INDEX idx_biometric_keys_user_tenant ON biometric_keys(user_id, tenant_id);
CREATE INDEX idx_biometric_challenges_expires ON biometric_challenges(expires_at);

-- Enable RLS
ALTER TABLE biometric_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE biometric_challenges ENABLE ROW LEVEL SECURITY;

-- RLS policies for biometric_keys
CREATE POLICY tenant_isolation_biometric_keys ON biometric_keys
    FOR ALL
    TO vault_app
    USING (tenant_id = current_tenant_id());

-- RLS policies for biometric_challenges (uses key_id reference)
CREATE POLICY tenant_isolation_biometric_challenges ON biometric_challenges
    FOR ALL
    TO vault_app
    USING (
        key_id IN (
            SELECT key_id FROM biometric_keys 
            WHERE tenant_id = current_tenant_id()
        )
    );

-- Comments
COMMENT ON TABLE biometric_keys IS 'Biometric authentication keys for users (Face ID, Touch ID, Fingerprint)';
COMMENT ON TABLE biometric_challenges IS 'Temporary challenges for biometric authentication (5-minute expiry)';
COMMENT ON COLUMN biometric_keys.public_key IS 'ECDSA P-256 public key in SEC1 format';
COMMENT ON COLUMN biometric_keys.key_id IS 'Client-generated unique identifier for the key';
COMMENT ON COLUMN biometric_keys.device_name IS 'Human-readable device name (e.g., iPhone 15 Pro)';
COMMENT ON COLUMN biometric_challenges.challenge IS 'Random challenge to be signed by client';
COMMENT ON COLUMN biometric_challenges.expires_at IS 'Challenge expiry time (5 minutes from creation)';
