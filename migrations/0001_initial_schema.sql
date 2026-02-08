-- Vault Database Schema v1
-- Multi-tenant user management with Row-Level Security (RLS)

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ============================================
-- Custom Types
-- ============================================

CREATE TYPE user_status AS ENUM ('pending', 'active', 'suspended', 'deactivated', 'deleted');
CREATE TYPE session_status AS ENUM ('active', 'expired', 'revoked', 'rotated');
CREATE TYPE mfa_method AS ENUM ('totp', 'email', 'sms', 'webauthn', 'backup_codes');
CREATE TYPE org_role AS ENUM ('owner', 'admin', 'member', 'guest', 'custom');
CREATE TYPE membership_status AS ENUM ('pending', 'active', 'suspended', 'removed');
CREATE TYPE sso_provider_type AS ENUM ('saml', 'oidc', 'microsoft', 'google', 'okta', 'onelogin', 'auth0', 'custom');
CREATE TYPE key_type AS ENUM ('jwt_signing', 'data_encryption', 'api_key_signing', 'session_encryption');

-- ============================================
-- Core Tables
-- ============================================

-- Tenants table (for tenant isolation)
CREATE TABLE tenants (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    slug VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'active',
    settings JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

-- Users table (with tenant isolation)
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    email_verified_at TIMESTAMPTZ,
    password_hash VARCHAR(255),  -- NULL for OAuth-only users
    status user_status NOT NULL DEFAULT 'pending',
    profile JSONB NOT NULL DEFAULT '{}',
    mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    mfa_methods JSONB NOT NULL DEFAULT '[]',
    last_login_at TIMESTAMPTZ,
    last_ip INET,
    failed_login_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TIMESTAMPTZ,
    password_changed_at TIMESTAMPTZ,
    password_change_required BOOLEAN NOT NULL DEFAULT FALSE,
    oauth_connections JSONB NOT NULL DEFAULT '[]',
    metadata JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ,
    
    -- Ensure email uniqueness within tenant
    UNIQUE(tenant_id, email)
);

-- Sessions table
CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    status session_status NOT NULL DEFAULT 'active',
    access_token_jti VARCHAR(255) NOT NULL,
    refresh_token_hash VARCHAR(255) NOT NULL,
    token_family VARCHAR(255) NOT NULL,
    ip_address INET,
    user_agent TEXT,
    device_fingerprint VARCHAR(255),
    device_info JSONB,
    location JSONB,
    mfa_verified BOOLEAN NOT NULL DEFAULT FALSE,
    mfa_verified_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_activity_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    revoked_reason TEXT
);

-- Organizations table
CREATE TABLE organizations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(255) NOT NULL,
    logo_url TEXT,
    description TEXT,
    website TEXT,
    metadata JSONB NOT NULL DEFAULT '{}',
    max_members INTEGER,
    sso_required BOOLEAN NOT NULL DEFAULT FALSE,
    sso_config JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ,
    
    -- Ensure slug uniqueness within tenant
    UNIQUE(tenant_id, slug)
);

-- Organization members table
CREATE TABLE organization_members (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role org_role NOT NULL DEFAULT 'member',
    permissions JSONB NOT NULL DEFAULT '[]',
    status membership_status NOT NULL DEFAULT 'pending',
    invited_by UUID REFERENCES users(id),
    invited_at TIMESTAMPTZ,
    joined_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- Ensure unique membership
    UNIQUE(organization_id, user_id)
);

-- Organization invitations table
CREATE TABLE organization_invitations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    role org_role NOT NULL DEFAULT 'member',
    invited_by UUID NOT NULL REFERENCES users(id),
    token VARCHAR(255) NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    accepted_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Audit log table (immutable)
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id),
    session_id UUID,
    action VARCHAR(255) NOT NULL,
    resource_type VARCHAR(255) NOT NULL,
    resource_id VARCHAR(255) NOT NULL,
    ip_address INET,
    user_agent TEXT,
    success BOOLEAN NOT NULL,
    error TEXT,
    metadata JSONB
    
    -- Partition by month for performance
    -- Note: Requires pg_partman or manual partitioning setup
);

-- Keys table (for tenant-specific encryption keys)
CREATE TABLE keys (
    id VARCHAR(255) PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    key_type key_type NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    version INTEGER NOT NULL DEFAULT 1,
    encrypted_secret TEXT,  -- Can be NULL for public-only keys
    public_key TEXT NOT NULL
);

-- Refresh tokens table (for rotation and revocation)
CREATE TABLE refresh_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_id UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) NOT NULL UNIQUE,
    token_family VARCHAR(255) NOT NULL,
    used BOOLEAN NOT NULL DEFAULT FALSE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    used_at TIMESTAMPTZ
);

-- Magic links table
CREATE TABLE magic_links (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    token_hash VARCHAR(255) NOT NULL UNIQUE,
    used BOOLEAN NOT NULL DEFAULT FALSE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    used_at TIMESTAMPTZ
);

-- Email verification tokens
CREATE TABLE email_verifications (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    token_hash VARCHAR(255) NOT NULL UNIQUE,
    used BOOLEAN NOT NULL DEFAULT FALSE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    used_at TIMESTAMPTZ
);

-- Password reset tokens
CREATE TABLE password_resets (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    token_hash VARCHAR(255) NOT NULL UNIQUE,
    used BOOLEAN NOT NULL DEFAULT FALSE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    used_at TIMESTAMPTZ
);

-- OAuth connections
CREATE TABLE oauth_connections (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider VARCHAR(100) NOT NULL,
    provider_user_id VARCHAR(255) NOT NULL,
    provider_username VARCHAR(255),
    email VARCHAR(255),
    access_token_encrypted TEXT,
    refresh_token_encrypted TEXT,
    token_expires_at TIMESTAMPTZ,
    raw_data JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    
    UNIQUE(tenant_id, provider, provider_user_id)
);

-- Rate limiting table
CREATE TABLE rate_limits (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    key VARCHAR(255) NOT NULL,  -- e.g., "ip:192.168.1.1" or "user:user_123"
    window_start TIMESTAMPTZ NOT NULL,
    request_count INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, key)
);

-- ============================================
-- Indexes for Performance
-- ============================================

-- User indexes
CREATE INDEX idx_users_tenant_email ON users(tenant_id, email) WHERE deleted_at IS NULL;
CREATE INDEX idx_users_status ON users(status) WHERE deleted_at IS NULL;
CREATE INDEX idx_users_created_at ON users(created_at DESC);

-- Session indexes
CREATE INDEX idx_sessions_user ON sessions(user_id, status) WHERE status = 'active';
CREATE INDEX idx_sessions_token_family ON sessions(token_family);
CREATE INDEX idx_sessions_expires ON sessions(expires_at);

-- Organization indexes
CREATE INDEX idx_orgs_tenant_slug ON organizations(tenant_id, slug) WHERE deleted_at IS NULL;
CREATE INDEX idx_org_members_org ON organization_members(organization_id, status);
CREATE INDEX idx_org_members_user ON organization_members(user_id);

-- Audit log indexes
CREATE INDEX idx_audit_logs_tenant ON audit_logs(tenant_id, timestamp DESC);
CREATE INDEX idx_audit_logs_user ON audit_logs(user_id, timestamp DESC);
CREATE INDEX idx_audit_logs_action ON audit_logs(action, timestamp DESC);

-- Token indexes
CREATE INDEX idx_refresh_tokens_session ON refresh_tokens(session_id);
CREATE INDEX idx_refresh_tokens_family ON refresh_tokens(token_family);
CREATE INDEX idx_magic_links_user ON magic_links(user_id);
CREATE INDEX idx_email_verifications_user ON email_verifications(user_id);
CREATE INDEX idx_password_resets_user ON password_resets(user_id);

-- ============================================
-- Row-Level Security (RLS) Policies
-- ============================================

-- Ensure application role exists
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vault_app') THEN
        CREATE ROLE vault_app;
    END IF;
END
$$;

-- Enable RLS on all tenant-isolated tables
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE organization_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE organization_invitations ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE refresh_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE magic_links ENABLE ROW LEVEL SECURITY;
ALTER TABLE email_verifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE password_resets ENABLE ROW LEVEL SECURITY;
ALTER TABLE oauth_connections ENABLE ROW LEVEL SECURITY;
ALTER TABLE rate_limits ENABLE ROW LEVEL SECURITY;

-- Create function to get current tenant ID from session
-- This will be set by the application on each connection
CREATE OR REPLACE FUNCTION current_tenant_id()
RETURNS UUID AS $$
BEGIN
    -- Get tenant_id from connection-level configuration
    -- Set by: SET app.current_tenant_id = 'uuid';
    RETURN NULLIF(current_setting('app.current_tenant_id', TRUE), '')::UUID;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create function to check if user is admin
CREATE OR REPLACE FUNCTION is_admin()
RETURNS BOOLEAN AS $$
DECLARE
    user_role TEXT;
BEGIN
    user_role := current_setting('app.current_user_role', TRUE);
    RETURN user_role = 'admin' OR user_role = 'owner';
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- ============================================
-- RLS Policies for Users Table
-- ============================================

-- Users can only see users in their tenant
CREATE POLICY tenant_isolation_users ON users
    FOR ALL
    TO vault_app
    USING (tenant_id = current_tenant_id());

-- Users can only see active users (unless admin)
CREATE POLICY active_users_only ON users
    FOR SELECT
    TO vault_app
    USING (
        tenant_id = current_tenant_id() AND 
        (deleted_at IS NULL OR is_admin())
    );

-- ============================================
-- RLS Policies for Sessions Table
-- ============================================

CREATE POLICY tenant_isolation_sessions ON sessions
    FOR ALL
    TO vault_app
    USING (tenant_id = current_tenant_id());

-- Users can only see their own sessions (unless admin)
CREATE POLICY own_sessions_only ON sessions
    FOR SELECT
    TO vault_app
    USING (
        tenant_id = current_tenant_id() AND 
        (user_id = current_setting('app.current_user_id', TRUE)::UUID OR is_admin())
    );

-- ============================================
-- RLS Policies for Organizations Table
-- ============================================

CREATE POLICY tenant_isolation_orgs ON organizations
    FOR ALL
    TO vault_app
    USING (tenant_id = current_tenant_id() AND deleted_at IS NULL);

-- ============================================
-- RLS Policies for Organization Members
-- ============================================

CREATE POLICY tenant_isolation_org_members ON organization_members
    FOR ALL
    TO vault_app
    USING (tenant_id = current_tenant_id());

-- Members can only update their own membership (unless admin)
CREATE POLICY own_membership_update ON organization_members
    FOR UPDATE
    TO vault_app
    USING (
        tenant_id = current_tenant_id() AND
        (user_id = current_setting('app.current_user_id', TRUE)::UUID OR is_admin())
    );

-- ============================================
-- RLS Policies for Audit Logs
-- ============================================

-- Audit logs are read-only for regular users, writable by system
CREATE POLICY tenant_isolation_audit ON audit_logs
    FOR SELECT
    TO vault_app
    USING (tenant_id = current_tenant_id());

-- Only admins can see all audit logs, users can see their own
CREATE POLICY audit_visibility ON audit_logs
    FOR SELECT
    TO vault_app
    USING (
        tenant_id = current_tenant_id() AND
        (user_id = current_setting('app.current_user_id', TRUE)::UUID OR is_admin())
    );

-- ============================================
-- RLS Policies for Keys Table
-- ============================================

-- Keys are only readable by service account, not regular users
CREATE POLICY tenant_isolation_keys ON keys
    FOR SELECT
    TO vault_app
    USING (tenant_id = current_tenant_id() AND is_active = TRUE);

-- ============================================
-- RLS Policies for Tokens Tables
-- ============================================

CREATE POLICY tenant_isolation_refresh_tokens ON refresh_tokens
    FOR ALL
    TO vault_app
    USING (tenant_id = current_tenant_id());

CREATE POLICY tenant_isolation_magic_links ON magic_links
    FOR ALL
    TO vault_app
    USING (tenant_id = current_tenant_id());

CREATE POLICY tenant_isolation_email_verifications ON email_verifications
    FOR ALL
    TO vault_app
    USING (tenant_id = current_tenant_id());

CREATE POLICY tenant_isolation_password_resets ON password_resets
    FOR ALL
    TO vault_app
    USING (tenant_id = current_tenant_id());

CREATE POLICY tenant_isolation_oauth ON oauth_connections
    FOR ALL
    TO vault_app
    USING (tenant_id = current_tenant_id());

-- ============================================
-- Triggers for Updated At
-- ============================================

CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_organizations_updated_at BEFORE UPDATE ON organizations
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_org_members_updated_at BEFORE UPDATE ON organization_members
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_rate_limits_updated_at BEFORE UPDATE ON rate_limits
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================
-- Views (for restricted column access)
-- ============================================

-- Public user view (excludes sensitive columns)
CREATE VIEW users_public AS
SELECT 
    id,
    tenant_id,
    email,
    email_verified,
    status,
    profile,
    mfa_enabled,
    last_login_at,
    created_at,
    updated_at
FROM users
WHERE deleted_at IS NULL;

-- Admin user view (includes all columns)
CREATE VIEW users_admin AS
SELECT *
FROM users;

-- Public organization view
CREATE VIEW organizations_public AS
SELECT 
    id,
    tenant_id,
    name,
    slug,
    logo_url,
    description,
    website,
    metadata,
    max_members,
    created_at,
    updated_at
FROM organizations
WHERE deleted_at IS NULL;

-- ============================================
-- Comments
-- ============================================

COMMENT ON TABLE users IS 'User accounts with tenant isolation';
COMMENT ON COLUMN users.password_hash IS 'Argon2id hash - NULL for OAuth-only users';
COMMENT ON COLUMN users.mfa_methods IS 'JSON array of configured MFA methods';

COMMENT ON TABLE sessions IS 'User sessions with device fingerprinting';
COMMENT ON COLUMN sessions.device_fingerprint IS 'Hash of IP + User-Agent for device detection';

COMMENT ON TABLE audit_logs IS 'Immutable audit trail - partitioned by month recommended';
COMMENT ON TABLE keys IS 'Tenant encryption keys - encrypted with master key';

COMMENT ON FUNCTION current_tenant_id() IS 'Returns the current tenant ID from session config';
