-- Anonymous/Guest Authentication Migration
-- Allows users to use the app without registering, then convert to full accounts later

-- ============================================
-- Update Users Table
-- ============================================

-- Add anonymous user columns to users table
ALTER TABLE users 
    ADD COLUMN IF NOT EXISTS is_anonymous BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS anonymous_session_id VARCHAR(255),
    ADD COLUMN IF NOT EXISTS anonymous_expires_at TIMESTAMPTZ;

-- Add comments for new columns
COMMENT ON COLUMN users.is_anonymous IS 'Whether this is an anonymous/guest user account';
COMMENT ON COLUMN users.anonymous_session_id IS 'Temporary session ID for anonymous users (NULL for regular users)';
COMMENT ON COLUMN users.anonymous_expires_at IS 'When the anonymous session expires (for cleanup jobs)';

-- Create index for anonymous user lookups
CREATE INDEX IF NOT EXISTS idx_users_anonymous 
    ON users(tenant_id, is_anonymous) 
    WHERE is_anonymous = TRUE AND deleted_at IS NULL;

-- Create unique index for anonymous session IDs
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_anonymous_session 
    ON users(anonymous_session_id) 
    WHERE anonymous_session_id IS NOT NULL AND deleted_at IS NULL;

-- Create index for anonymous session cleanup
CREATE INDEX IF NOT EXISTS idx_users_anonymous_expires 
    ON users(anonymous_expires_at) 
    WHERE is_anonymous = TRUE AND deleted_at IS NULL;

-- ============================================
-- Anonymous Session Tracking Table
-- ============================================

-- Optional: Store detailed anonymous session metadata
CREATE TABLE IF NOT EXISTS anonymous_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    anonymous_session_id VARCHAR(255) NOT NULL UNIQUE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_from_ip INET,
    user_agent TEXT,
    metadata JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    last_activity_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    converted_to_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    converted_at TIMESTAMPTZ
);

-- Indexes for anonymous sessions
CREATE INDEX IF NOT EXISTS idx_anon_sessions_session_id ON anonymous_sessions(anonymous_session_id);
CREATE INDEX IF NOT EXISTS idx_anon_sessions_user_id ON anonymous_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_anon_sessions_expires ON anonymous_sessions(expires_at) WHERE converted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_anon_sessions_converted ON anonymous_sessions(converted_to_user_id) WHERE converted_to_user_id IS NOT NULL;

-- Add comment
COMMENT ON TABLE anonymous_sessions IS 'Tracks anonymous/guest session metadata and conversion history';

-- ============================================
-- Anonymous Data Storage Table
-- ============================================

-- Store data created by anonymous users before conversion
CREATE TABLE IF NOT EXISTS anonymous_data (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    anonymous_session_id VARCHAR(255) NOT NULL REFERENCES anonymous_sessions(anonymous_session_id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    data_type VARCHAR(100) NOT NULL,
    data_key VARCHAR(255) NOT NULL,
    data_value JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    migrated_to_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    migrated_at TIMESTAMPTZ,
    
    UNIQUE(anonymous_session_id, data_type, data_key)
);

-- Indexes for anonymous data
CREATE INDEX IF NOT EXISTS idx_anon_data_session ON anonymous_data(anonymous_session_id);
CREATE INDEX IF NOT EXISTS idx_anon_data_type ON anonymous_data(data_type);
CREATE INDEX IF NOT EXISTS idx_anon_data_migrated ON anonymous_data(migrated_to_user_id) WHERE migrated_to_user_id IS NOT NULL;

-- Add comment
COMMENT ON TABLE anonymous_data IS 'Temporary data storage for anonymous users before account conversion';

-- Trigger for updated_at
DROP TRIGGER IF EXISTS update_anonymous_data_updated_at ON anonymous_data;
CREATE TRIGGER update_anonymous_data_updated_at
    BEFORE UPDATE ON anonymous_data
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ============================================
-- RLS Policies
-- ============================================

-- Enable RLS on new tables
ALTER TABLE anonymous_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE anonymous_data ENABLE ROW LEVEL SECURITY;

-- Anonymous sessions policies
DROP POLICY IF EXISTS anonymous_sessions_tenant_isolation ON anonymous_sessions;
CREATE POLICY anonymous_sessions_tenant_isolation ON anonymous_sessions
    FOR ALL
    TO vault_app
    USING (tenant_id = current_tenant_id());

-- Anonymous data policies
DROP POLICY IF EXISTS anonymous_data_tenant_isolation ON anonymous_data;
CREATE POLICY anonymous_data_tenant_isolation ON anonymous_data
    FOR ALL
    TO vault_app
    USING (tenant_id = current_tenant_id());

-- ============================================
-- Permissions
-- ============================================

GRANT SELECT, INSERT, UPDATE, DELETE ON anonymous_sessions TO vault_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON anonymous_data TO vault_app;

-- ============================================
-- Cleanup Function
-- ============================================

-- Function to clean up expired anonymous sessions
CREATE OR REPLACE FUNCTION cleanup_expired_anonymous_sessions()
RETURNS TABLE (
    deleted_sessions BIGINT,
    deleted_users BIGINT,
    deleted_data BIGINT
) AS $$
DECLARE
    v_deleted_sessions BIGINT;
    v_deleted_users BIGINT;
    v_deleted_data BIGINT;
BEGIN
    -- Delete expired anonymous data first (FK constraint)
    DELETE FROM anonymous_data
    WHERE anonymous_session_id IN (
        SELECT anonymous_session_id 
        FROM anonymous_sessions 
        WHERE expires_at < NOW() - INTERVAL '24 hours'
          AND converted_at IS NULL
    );
    GET DIAGNOSTICS v_deleted_data = ROW_COUNT;

    -- Delete expired anonymous sessions
    DELETE FROM anonymous_sessions
    WHERE expires_at < NOW() - INTERVAL '24 hours'
      AND converted_at IS NULL;
    GET DIAGNOSTICS v_deleted_sessions = ROW_COUNT;

    -- Soft delete expired anonymous users (older than 7 days)
    UPDATE users 
    SET deleted_at = NOW(),
        status = 'deleted'::user_status,
        updated_at = NOW()
    WHERE is_anonymous = TRUE 
      AND created_at < NOW() - INTERVAL '7 days'
      AND deleted_at IS NULL
      AND anonymous_session_id IS NOT NULL;
    GET DIAGNOSTICS v_deleted_users = ROW_COUNT;

    RETURN QUERY SELECT v_deleted_sessions, v_deleted_users, v_deleted_data;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION cleanup_expired_anonymous_sessions() IS 'Removes expired anonymous sessions, data, and users';

GRANT EXECUTE ON FUNCTION cleanup_expired_anonymous_sessions() TO vault_app;

-- ============================================
-- View for Anonymous User Statistics
-- ============================================

CREATE OR REPLACE VIEW anonymous_user_stats AS
SELECT 
    tenant_id,
    COUNT(*) FILTER (WHERE deleted_at IS NULL AND is_anonymous = TRUE) as total_anonymous,
    COUNT(*) FILTER (WHERE deleted_at IS NULL AND is_anonymous = TRUE AND created_at > NOW() - INTERVAL '24 hours') as new_today,
    COUNT(*) FILTER (WHERE deleted_at IS NULL AND is_anonymous = TRUE AND created_at > NOW() - INTERVAL '7 days') as new_this_week,
    COUNT(*) FILTER (WHERE is_anonymous = TRUE AND anonymous_session_id IS NULL) as converted_to_full,
    COUNT(*) FILTER (WHERE deleted_at IS NOT NULL AND is_anonymous = TRUE) as expired_deleted
FROM users
WHERE is_anonymous = TRUE
GROUP BY tenant_id;

COMMENT ON VIEW anonymous_user_stats IS 'Statistics about anonymous user usage per tenant';

GRANT SELECT ON anonymous_user_stats TO vault_app;
