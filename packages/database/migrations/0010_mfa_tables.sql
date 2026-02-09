-- MFA tables for TOTP, WebAuthn, and backup codes

-- Create MFA method type enum
CREATE TYPE mfa_method AS ENUM ('totp', 'email', 'sms', 'webauthn', 'backup_codes');

-- User MFA methods table
CREATE TABLE user_mfa_methods (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    method_type mfa_method NOT NULL,
    -- For TOTP: encrypted secret
    secret_encrypted TEXT,
    -- For WebAuthn: credential data
    public_key TEXT,
    credential_id TEXT,
    -- Common fields
    verified BOOLEAN NOT NULL DEFAULT FALSE,
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    
    -- Ensure unique methods per user
    UNIQUE(tenant_id, user_id, method_type, credential_id)
);

-- Backup codes table
CREATE TABLE user_backup_codes (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,
    used BOOLEAN NOT NULL DEFAULT FALSE,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX idx_mfa_methods_user ON user_mfa_methods(tenant_id, user_id);
CREATE INDEX idx_mfa_methods_enabled ON user_mfa_methods(tenant_id, user_id, enabled) WHERE enabled = true;
CREATE INDEX idx_mfa_methods_type ON user_mfa_methods(method_type);
CREATE INDEX idx_backup_codes_user ON user_backup_codes(tenant_id, user_id);
CREATE INDEX idx_backup_codes_unused ON user_backup_codes(tenant_id, user_id, used) WHERE used = false;

-- Enable RLS
ALTER TABLE user_mfa_methods ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_backup_codes ENABLE ROW LEVEL SECURITY;

-- RLS policies
CREATE POLICY tenant_isolation_mfa_methods ON user_mfa_methods
    FOR ALL
    TO vault_app
    USING (tenant_id = current_tenant_id());

CREATE POLICY tenant_isolation_backup_codes ON user_backup_codes
    FOR ALL
    TO vault_app
    USING (tenant_id = current_tenant_id());

-- Trigger to update updated_at
CREATE TRIGGER update_mfa_methods_updated_at BEFORE UPDATE ON user_mfa_methods
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Comments
COMMENT ON TABLE user_mfa_methods IS 'MFA methods configured by users (TOTP, WebAuthn)';
COMMENT ON TABLE user_backup_codes IS 'Backup codes for account recovery';
COMMENT ON COLUMN user_mfa_methods.secret_encrypted IS 'AES-256 encrypted TOTP secret';
COMMENT ON COLUMN user_backup_codes.code_hash IS 'Argon2id hash of the backup code';
