-- Add impersonator_id column to audit_logs for tracking actions during impersonation

-- Add column if it doesn't exist
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 
        FROM information_schema.columns 
        WHERE table_name = 'audit_logs' 
        AND column_name = 'impersonator_id'
    ) THEN
        ALTER TABLE audit_logs ADD COLUMN impersonator_id UUID;
    END IF;
END $$;

-- Add index for efficient queries on impersonator_id
CREATE INDEX IF NOT EXISTS idx_audit_logs_impersonator ON audit_logs(impersonator_id) 
    WHERE impersonator_id IS NOT NULL;

-- Add index for finding all actions during a specific impersonation session
CREATE INDEX IF NOT EXISTS idx_audit_logs_impersonation ON audit_logs(session_id, impersonator_id) 
    WHERE impersonator_id IS NOT NULL;

-- Add comment for documentation
COMMENT ON COLUMN audit_logs.impersonator_id IS 
    'ID of the admin user who was impersonating when this action was performed. NULL if not an impersonated action.';

-- Update RLS policies to allow querying by impersonator_id
DROP POLICY IF EXISTS audit_logs_impersonator_view ON audit_logs;

-- Allow admins to see audit logs where they were the impersonator
CREATE POLICY audit_logs_impersonator_view ON audit_logs
    FOR SELECT
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::UUID
        AND (
            -- User can see their own logs
            user_id = current_setting('app.current_user_id', true)::UUID
            -- Admin can see all logs in tenant
            OR EXISTS (
                SELECT 1 FROM users 
                WHERE id = current_setting('app.current_user_id', true)::UUID
                AND (is_admin = true OR metadata->>'role' = 'superadmin')
            )
            -- User can see logs where they were the impersonator
            OR impersonator_id = current_setting('app.current_user_id', true)::UUID
        )
    );
