-- Session limits and subscription tier support

-- Add subscription tier type
CREATE TYPE subscription_tier AS ENUM ('free', 'pro', 'enterprise', 'custom');

-- Add session limits configuration to tenants table
ALTER TABLE tenants 
    ADD COLUMN subscription_tier subscription_tier NOT NULL DEFAULT 'free',
    ADD COLUMN session_limits JSONB NOT NULL DEFAULT '{}',
    ADD COLUMN max_sessions_per_user INTEGER,
    ADD COLUMN eviction_policy VARCHAR(50) DEFAULT 'oldest_first';

-- Update existing tenants with default session limits based on tier
UPDATE tenants SET 
    max_sessions_per_user = CASE 
        WHEN subscription_tier = 'free' THEN 2
        WHEN subscription_tier = 'pro' THEN 5
        WHEN subscription_tier = 'enterprise' THEN NULL  -- Unlimited
        ELSE 5
    END,
    session_limits = jsonb_build_object(
        'max_concurrent_sessions', CASE 
            WHEN subscription_tier = 'free' THEN 2
            WHEN subscription_tier = 'pro' THEN 5
            WHEN subscription_tier = 'enterprise' THEN 0  -- 0 means unlimited
            ELSE 5
        END,
        'eviction_policy', 'oldest_first',
        'enforce_for_ip', false,
        'max_sessions_per_ip', 3
    );

-- Add index for session limit queries
CREATE INDEX idx_sessions_user_status ON sessions(user_id, status, created_at) 
    WHERE status = 'active';

-- Create function to get active session count for a user
CREATE OR REPLACE FUNCTION get_active_session_count(p_user_id UUID)
RETURNS INTEGER AS $$
DECLARE
    v_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO v_count
    FROM sessions
    WHERE user_id = p_user_id
      AND status = 'active'
      AND expires_at > NOW();
    
    RETURN v_count;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create function to check if user can create new session
CREATE OR REPLACE FUNCTION can_create_session(
    p_tenant_id UUID,
    p_user_id UUID,
    p_max_sessions INTEGER DEFAULT 5
)
RETURNS BOOLEAN AS $$
DECLARE
    v_current_count INTEGER;
    v_tier_max INTEGER;
BEGIN
    -- Get current active session count
    v_current_count := get_active_session_count(p_user_id);
    
    -- Get max sessions from tenant config (if set)
    SELECT COALESCE(max_sessions_per_user, p_max_sessions)
    INTO v_tier_max
    FROM tenants
    WHERE id = p_tenant_id;
    
    -- NULL or 0 means unlimited
    IF v_tier_max IS NULL OR v_tier_max = 0 THEN
        RETURN TRUE;
    END IF;
    
    RETURN v_current_count < v_tier_max;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create function to revoke oldest sessions for a user
CREATE OR REPLACE FUNCTION revoke_oldest_sessions(
    p_tenant_id UUID,
    p_user_id UUID,
    p_keep_count INTEGER
)
RETURNS INTEGER AS $$
DECLARE
    v_revoked_count INTEGER;
BEGIN
    WITH revoked AS (
        UPDATE sessions
        SET status = 'revoked',
            revoked_at = NOW(),
            revoked_reason = 'session_limit_eviction',
            updated_at = NOW()
        WHERE id IN (
            SELECT id FROM sessions
            WHERE tenant_id = p_tenant_id
              AND user_id = p_user_id
              AND status = 'active'
              AND expires_at > NOW()
            ORDER BY created_at ASC
            OFFSET p_keep_count
        )
        RETURNING id
    )
    SELECT COUNT(*) INTO v_revoked_count FROM revoked;
    
    RETURN v_revoked_count;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Comments
COMMENT ON COLUMN tenants.session_limits IS 'JSON configuration for session limits';
COMMENT ON COLUMN tenants.max_sessions_per_user IS 'Maximum concurrent sessions per user (NULL = unlimited)';
COMMENT ON COLUMN tenants.eviction_policy IS 'Policy when limit reached: oldest_first, newest_first, deny_new';
COMMENT ON FUNCTION get_active_session_count IS 'Returns count of active sessions for a user';
COMMENT ON FUNCTION can_create_session IS 'Checks if user can create a new session';
COMMENT ON FUNCTION revoke_oldest_sessions IS 'Revokes oldest sessions keeping only specified count';
