-- Vault Database Security Roles
-- Sets up PostgreSQL roles with principle of least privilege

-- ============================================
-- Drop existing roles (for clean setup)
-- ============================================
-- Note: Only run in development! In production, use ALTER instead.

-- DROP ROLE IF EXISTS vault_admin;
-- DROP ROLE IF EXISTS vault_app;
-- DROP ROLE IF EXISTS vault_readonly;
-- DROP ROLE IF EXISTS vault_service;

-- ============================================
-- Create Roles
-- ============================================

-- vault_admin: Full database access (for migrations, admin tasks)
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vault_admin') THEN
        CREATE ROLE vault_admin WITH
            LOGIN
            PASSWORD NULL  -- Set via environment variable
            CREATEDB       -- Can create databases (for migrations)
            CREATEROLE;    -- Can create other roles
    END IF;
END
$$;

-- vault_app: Application role (limited permissions)
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vault_app') THEN
        CREATE ROLE vault_app WITH
            LOGIN
            PASSWORD NULL;  -- Set via environment variable
    END IF;
END
$$;

-- vault_readonly: Read-only access (for analytics, reporting)
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vault_readonly') THEN
        CREATE ROLE vault_readonly WITH
            LOGIN
            PASSWORD NULL;
    END IF;
END
$$;

-- vault_service: Service account for background jobs
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vault_service') THEN
        CREATE ROLE vault_service WITH
            LOGIN
            PASSWORD NULL;
    END IF;
END
$$;

-- ============================================
-- Grant Schema Usage
-- ============================================

GRANT USAGE ON SCHEMA public TO vault_admin, vault_app, vault_readonly, vault_service;

-- ============================================
-- vault_admin Permissions (Full Access)
-- ============================================

-- Grant all on all tables
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO vault_admin;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO vault_admin;

-- Future tables automatically
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO vault_admin;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO vault_admin;

-- Allow bypassing RLS (for migrations and admin tasks)
ALTER ROLE vault_admin BYPASSRLS;

-- ============================================
-- vault_app Permissions (Application)
-- ============================================

-- Tables: SELECT, INSERT, UPDATE, DELETE
-- Audit logs: INSERT only (immutable)

-- Users table: Full CRUD
GRANT SELECT, INSERT, UPDATE, DELETE ON users TO vault_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON users_public TO vault_app;
GRANT SELECT ON users_admin TO vault_app;

-- Sessions table: Full CRUD
GRANT SELECT, INSERT, UPDATE, DELETE ON sessions TO vault_app;

-- Organizations table: Full CRUD
GRANT SELECT, INSERT, UPDATE, DELETE ON organizations TO vault_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON organizations_public TO vault_app;

-- Organization members: Full CRUD
GRANT SELECT, INSERT, UPDATE, DELETE ON organization_members TO vault_app;

-- Organization invitations: Full CRUD
GRANT SELECT, INSERT, UPDATE, DELETE ON organization_invitations TO vault_app;

-- Audit logs: INSERT only (immutable, for logging)
GRANT INSERT ON audit_logs TO vault_app;
GRANT SELECT ON audit_logs TO vault_app;

-- Keys: SELECT only (keys are managed separately)
GRANT SELECT ON keys TO vault_app;

-- Refresh tokens: Full CRUD
GRANT SELECT, INSERT, UPDATE, DELETE ON refresh_tokens TO vault_app;

-- Magic links: Full CRUD
GRANT SELECT, INSERT, UPDATE, DELETE ON magic_links TO vault_app;

-- Email verifications: Full CRUD
GRANT SELECT, INSERT, UPDATE, DELETE ON email_verifications TO vault_app;

-- Password resets: Full CRUD
GRANT SELECT, INSERT, UPDATE, DELETE ON password_resets TO vault_app;

-- OAuth connections: Full CRUD
GRANT SELECT, INSERT, UPDATE, DELETE ON oauth_connections TO vault_app;

-- Rate limits: Full CRUD
GRANT SELECT, INSERT, UPDATE, DELETE ON rate_limits TO vault_app;

-- Tenants: SELECT only (managed separately)
GRANT SELECT ON tenants TO vault_app;

-- Sequences
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO vault_app;

-- Future tables
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO vault_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE ON SEQUENCES TO vault_app;

-- Future tables: audit_logs should only get INSERT
-- This is handled by separate policy

-- ============================================
-- vault_readonly Permissions (Analytics)
-- ============================================

-- Read-only access to non-sensitive tables
GRANT SELECT ON users_public TO vault_readonly;
GRANT SELECT ON organizations_public TO vault_readonly;
GRANT SELECT ON organization_members TO vault_readonly;
GRANT SELECT ON audit_logs TO vault_readonly;
GRANT SELECT ON tenants TO vault_readonly;

-- No access to:
-- - users (sensitive data)
-- - sessions (sensitive)
-- - keys (encryption keys)
-- - refresh_tokens
-- - magic_links
-- - email_verifications
-- - password_resets
-- - oauth_connections

-- Future tables
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO vault_readonly;

-- ============================================
-- vault_service Permissions (Background Jobs)
-- ============================================

-- Can clean up expired data
GRANT SELECT, DELETE ON sessions TO vault_service;
GRANT SELECT, DELETE ON refresh_tokens TO vault_service;
GRANT SELECT, DELETE ON magic_links TO vault_service;
GRANT SELECT, DELETE ON email_verifications TO vault_service;
GRANT SELECT, DELETE ON password_resets TO vault_service;
GRANT SELECT, DELETE ON rate_limits TO vault_service;
GRANT SELECT, DELETE ON organization_invitations TO vault_service;

-- Can update audit logs (for maintenance)
GRANT SELECT, DELETE ON audit_logs TO vault_service;

-- Can read users for notifications
GRANT SELECT ON users TO vault_service;

-- Can update user lockout status
GRANT UPDATE (failed_login_attempts, locked_until) ON users TO vault_service;

-- Sequences
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO vault_service;

-- ============================================
-- Column-Level Security
-- ============================================

-- Revoke sensitive column access from vault_app
-- Note: In PostgreSQL, column-level REVOKE must be done at the table level

-- Users table: Restrict password_hash access
-- Application should only update password_hash, never read it directly
REVOKE SELECT (password_hash) ON users FROM vault_app;

-- OAuth connections: Token columns are write-only
REVOKE SELECT (access_token_encrypted, refresh_token_encrypted) ON oauth_connections FROM vault_app;
GRANT INSERT (access_token_encrypted, refresh_token_encrypted) ON oauth_connections TO vault_app;
GRANT UPDATE (access_token_encrypted, refresh_token_encrypted) ON oauth_connections TO vault_app;

-- Keys: Encrypted secret is service-only
REVOKE SELECT (encrypted_secret) ON keys FROM vault_app;

-- ============================================
-- Row-Level Security Force
-- ============================================

-- Ensure RLS is always applied (even for table owners)
-- This is critical for multi-tenant security

ALTER ROLE vault_app SET row_security = ON;
ALTER ROLE vault_readonly SET row_security = ON;

-- Note: vault_admin BYPASSRLS is set above
-- vault_service needs to bypass RLS for cleanup jobs
ALTER ROLE vault_service BYPASSRLS;

-- ============================================
-- Connection Limits
-- ============================================

-- Limit concurrent connections per role
ALTER ROLE vault_app CONNECTION LIMIT 100;
ALTER ROLE vault_readonly CONNECTION LIMIT 20;
ALTER ROLE vault_service CONNECTION LIMIT 10;

-- ============================================
-- Statement Timeout
-- ============================================

-- Prevent runaway queries
ALTER ROLE vault_app SET statement_timeout = '30s';
ALTER ROLE vault_readonly SET statement_timeout = '60s';
ALTER ROLE vault_service SET statement_timeout = '300s';

-- ============================================
-- Comments
-- ============================================

COMMENT ON ROLE vault_admin IS 'Full database access for migrations and admin tasks';
COMMENT ON ROLE vault_app IS 'Application role with tenant-scoped access via RLS';
COMMENT ON ROLE vault_readonly IS 'Read-only access for analytics and reporting';
COMMENT ON ROLE vault_service IS 'Background job service with cleanup permissions';

-- ============================================
-- Security Check Function
-- ============================================

CREATE OR REPLACE FUNCTION check_security_setup()
RETURNS TABLE (
    check_name TEXT,
    status TEXT,
    details TEXT
) AS $$
BEGIN
    -- Check RLS is enabled on critical tables
    RETURN QUERY
    SELECT 
        'RLS Enabled: ' || tablename AS check_name,
        CASE WHEN rowsecurity THEN 'PASS' ELSE 'FAIL' END AS status,
        CASE WHEN rowsecurity THEN 'Row-level security is enabled' 
             ELSE 'Row-level security is NOT enabled - SECURITY RISK!' END AS details
    FROM pg_tables
    JOIN pg_class ON pg_class.relname = tablename
    WHERE schemaname = 'public' 
      AND tablename IN ('users', 'sessions', 'organizations', 'audit_logs');
    
    -- Check vault_app does not have BYPASSRLS
    RETURN QUERY
    SELECT 
        'BYPASSRLS Check: vault_app' AS check_name,
        CASE WHEN rolbypassrls THEN 'FAIL' ELSE 'PASS' END AS status,
        CASE WHEN rolbypassrls THEN 'vault_app can bypass RLS - SECURITY RISK!'
             ELSE 'vault_app cannot bypass RLS' END AS details
    FROM pg_roles 
    WHERE rolname = 'vault_app';
    
    -- Check password authentication is required
    RETURN QUERY
    SELECT 
        'Password Auth: ' || rolname AS check_name,
        CASE WHEN rolpassword = '' THEN 'WARN' ELSE 'PASS' END AS status,
        CASE WHEN rolpassword = '' THEN 'Role has no password set'
             ELSE 'Role has password configured' END AS details
    FROM pg_roles 
    WHERE rolname IN ('vault_admin', 'vault_app', 'vault_readonly', 'vault_service');
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Run security check
SELECT * FROM check_security_setup();
