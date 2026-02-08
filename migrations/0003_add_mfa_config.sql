-- Add MFA configuration column to users table
-- This stores TOTP secrets, backup codes, and other MFA data

-- Add mfa_config column
ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_config JSONB DEFAULT '{}';

-- Create index for MFA-enabled users
CREATE INDEX IF NOT EXISTS idx_users_mfa_enabled ON users(mfa_enabled) WHERE mfa_enabled = true;

-- Comment on the column
COMMENT ON COLUMN users.mfa_config IS 'MFA configuration including TOTP secrets, backup codes, etc. (encrypted fields should be encrypted at application level)';
