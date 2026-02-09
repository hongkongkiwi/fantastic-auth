-- Impersonation Sessions Table
-- Tracks all admin impersonation sessions for audit and security compliance

CREATE TABLE IF NOT EXISTS impersonation_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    admin_id UUID NOT NULL,
    target_user_id UUID NOT NULL,
    tenant_id UUID NOT NULL,
    reason TEXT NOT NULL,
    session_token VARCHAR(255) UNIQUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    ended_at TIMESTAMPTZ,
    ended_by UUID,
    is_active BOOLEAN DEFAULT true
);

-- Indexes for common queries
CREATE INDEX IF NOT EXISTS idx_impersonation_admin ON impersonation_sessions(admin_id);
CREATE INDEX IF NOT EXISTS idx_impersonation_target ON impersonation_sessions(target_user_id);
CREATE INDEX IF NOT EXISTS idx_impersonation_tenant ON impersonation_sessions(tenant_id);
CREATE INDEX IF NOT EXISTS idx_impersonation_active ON impersonation_sessions(is_active) WHERE is_active = true;
CREATE INDEX IF NOT EXISTS idx_impersonation_token ON impersonation_sessions(session_token) WHERE session_token IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_impersonation_expires ON impersonation_sessions(expires_at) WHERE is_active = true;

-- Foreign key constraints (optional, depending on your RLS setup)
-- Note: These are commented out if you're using RLS strictly
-- ALTER TABLE impersonation_sessions 
--     ADD CONSTRAINT fk_impersonation_admin 
--     FOREIGN KEY (admin_id) REFERENCES users(id) ON DELETE CASCADE;

-- ALTER TABLE impersonation_sessions 
--     ADD CONSTRAINT fk_impersonation_target 
--     FOREIGN KEY (target_user_id) REFERENCES users(id) ON DELETE CASCADE;

-- RLS Policies for impersonation_sessions
ALTER TABLE impersonation_sessions ENABLE ROW LEVEL SECURITY;

-- Policy: Users can only see impersonation sessions in their tenant
CREATE POLICY impersonation_tenant_isolation ON impersonation_sessions
    USING (tenant_id = current_setting('app.current_tenant_id', true)::UUID);

-- Policy: Admins can view all impersonation sessions in their tenant
CREATE POLICY impersonation_admin_view ON impersonation_sessions
    FOR SELECT
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::UUID
        AND EXISTS (
            SELECT 1 FROM users 
            WHERE id = current_setting('app.current_user_id', true)::UUID
            AND (is_admin = true OR metadata->>'role' = 'superadmin')
        )
    );

-- Policy: Only admins can create impersonation sessions
CREATE POLICY impersonation_admin_insert ON impersonation_sessions
    FOR INSERT
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::UUID
        AND EXISTS (
            SELECT 1 FROM users 
            WHERE id = current_setting('app.current_user_id', true)::UUID
            AND (is_admin = true OR metadata->>'role' = 'superadmin')
        )
    );

-- Policy: Only the impersonating admin or superadmin can end a session
CREATE POLICY impersonation_admin_update ON impersonation_sessions
    FOR UPDATE
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::UUID
        AND (
            admin_id = current_setting('app.current_user_id', true)::UUID
            OR EXISTS (
                SELECT 1 FROM users 
                WHERE id = current_setting('app.current_user_id', true)::UUID
                AND metadata->>'role' = 'superadmin'
            )
        )
    );

-- Grant permissions
GRANT SELECT, INSERT, UPDATE ON impersonation_sessions TO vault_app;
GRANT USAGE ON SEQUENCE impersonation_sessions_id_seq TO vault_app;

-- Add comment for documentation
COMMENT ON TABLE impersonation_sessions IS 'Tracks admin impersonation sessions for audit compliance';
COMMENT ON COLUMN impersonation_sessions.reason IS 'Required justification for impersonation (min 5 chars)';
COMMENT ON COLUMN impersonation_sessions.session_token IS 'Internal token for session validation';
