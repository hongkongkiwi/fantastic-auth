-- SCIM 2.0 Enhancements Migration
-- Adds additional tables and columns for full RFC 7643/7644 compliance

-- ============================================
-- Enhanced SCIM Tokens Table
-- ============================================

-- Drop and recreate scim_tokens with additional columns if needed
ALTER TABLE scim_tokens 
    ADD COLUMN IF NOT EXISTS name VARCHAR(255) NOT NULL DEFAULT 'SCIM Token',
    ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS created_by UUID REFERENCES users(id) ON DELETE SET NULL;

-- Add index for token lookup
CREATE INDEX IF NOT EXISTS idx_scim_tokens_hash ON scim_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_scim_tokens_status ON scim_tokens(tenant_id, status) WHERE status = 'active';

-- ============================================
-- SCIM Audit Logs Table
-- ============================================

CREATE TABLE IF NOT EXISTS scim_audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    token_id UUID NOT NULL REFERENCES scim_tokens(id) ON DELETE CASCADE,
    action VARCHAR(50) NOT NULL, -- create, update, delete, patch, get, list
    resource_type VARCHAR(50) NOT NULL, -- User, Group
    resource_id VARCHAR(255) NOT NULL,
    ip_address INET,
    user_agent TEXT,
    request_body JSONB,
    response_status INTEGER,
    success BOOLEAN NOT NULL DEFAULT TRUE,
    error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for audit logs
CREATE INDEX IF NOT EXISTS idx_scim_audit_logs_tenant ON scim_audit_logs(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scim_audit_logs_token ON scim_audit_logs(token_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scim_audit_logs_action ON scim_audit_logs(tenant_id, action, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scim_audit_logs_resource ON scim_audit_logs(tenant_id, resource_type, resource_id);

-- Partition by month recommendation comment
COMMENT ON TABLE scim_audit_logs IS 'SCIM API audit trail - consider partitioning by month for high volume';

-- ============================================
-- SCIM Group Members Junction Table
-- ============================================

-- Proper junction table for group memberships
CREATE TABLE IF NOT EXISTS scim_group_members (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    group_id UUID NOT NULL REFERENCES scim_groups(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES scim_users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    UNIQUE(tenant_id, group_id, user_id)
);

-- Indexes for group members
CREATE INDEX IF NOT EXISTS idx_scim_group_members_group ON scim_group_members(group_id);
CREATE INDEX IF NOT EXISTS idx_scim_group_members_user ON scim_group_members(user_id);
CREATE INDEX IF NOT EXISTS idx_scim_group_members_tenant ON scim_group_members(tenant_id);

-- ============================================
-- RLS Policies for New Tables
-- ============================================

-- Enable RLS
ALTER TABLE scim_audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE scim_group_members ENABLE ROW LEVEL SECURITY;

-- RLS policies for audit logs
CREATE POLICY tenant_isolation_scim_audit_logs ON scim_audit_logs
    FOR ALL TO vault_app
    USING (tenant_id = current_tenant_id());

-- RLS policies for group members
CREATE POLICY tenant_isolation_scim_group_members ON scim_group_members
    FOR ALL TO vault_app
    USING (tenant_id = current_tenant_id());

-- ============================================
-- SCIM Settings Configuration Table
-- ============================================

CREATE TABLE IF NOT EXISTS scim_settings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    
    -- User provisioning settings
    auto_create_users BOOLEAN NOT NULL DEFAULT TRUE,
    auto_deactivate_users BOOLEAN NOT NULL DEFAULT TRUE,
    sync_passwords BOOLEAN NOT NULL DEFAULT FALSE, -- Usually false for SCIM
    default_user_role VARCHAR(50) NOT NULL DEFAULT 'member',
    
    -- Group provisioning settings
    sync_groups BOOLEAN NOT NULL DEFAULT TRUE,
    sync_group_members BOOLEAN NOT NULL DEFAULT TRUE,
    
    -- Attribute mappings (JSON for flexibility)
    attribute_mappings JSONB NOT NULL DEFAULT '{
        "userName": "email",
        "name.givenName": "profile.first_name",
        "name.familyName": "profile.last_name",
        "emails": "email"
    }',
    
    -- Filtering and customization
    allowed_operations JSONB NOT NULL DEFAULT '["GET", "POST", "PUT", "PATCH", "DELETE"]',
    
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    UNIQUE(tenant_id)
);

-- Index and RLS
CREATE INDEX IF NOT EXISTS idx_scim_settings_tenant ON scim_settings(tenant_id);
ALTER TABLE scim_settings ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_scim_settings ON scim_settings
    FOR ALL TO vault_app
    USING (tenant_id = current_tenant_id());

-- Trigger for updated_at
CREATE TRIGGER update_scim_settings_updated_at 
    BEFORE UPDATE ON scim_settings 
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

-- ============================================
-- Enhanced SCIM Users Table
-- ============================================

-- Add missing columns to scim_users
ALTER TABLE scim_users
    ADD COLUMN IF NOT EXISTS emails JSONB,
    ADD COLUMN IF NOT EXISTS name JSONB,
    ADD COLUMN IF NOT EXISTS display_name VARCHAR(255),
    ADD COLUMN IF NOT EXISTS locale VARCHAR(10),
    ADD COLUMN IF NOT EXISTS timezone VARCHAR(50),
    ADD COLUMN IF NOT EXISTS title VARCHAR(100),
    ADD COLUMN IF NOT EXISTS department VARCHAR(100),
    ADD COLUMN IF NOT EXISTS organization VARCHAR(100);

-- Add indexes for common filters
CREATE INDEX IF NOT EXISTS idx_scim_users_external_id ON scim_users(tenant_id, external_id) WHERE external_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_scim_users_active ON scim_users(tenant_id, active);

-- ============================================
-- Enhanced SCIM Groups Table
-- ============================================

-- Add missing columns to scim_groups
ALTER TABLE scim_groups
    ADD COLUMN IF NOT EXISTS external_id VARCHAR(255);

-- Add index for external_id lookups
CREATE INDEX IF NOT EXISTS idx_scim_groups_external_id ON scim_groups(tenant_id, external_id) WHERE external_id IS NOT NULL;

-- ============================================
-- SCIM Rate Limiting Table
-- ============================================

CREATE TABLE IF NOT EXISTS scim_rate_limits (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    token_id UUID NOT NULL REFERENCES scim_tokens(id) ON DELETE CASCADE,
    window_start TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    request_count INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    UNIQUE(tenant_id, token_id, window_start)
);

-- Index and RLS
CREATE INDEX IF NOT EXISTS idx_scim_rate_limits_token ON scim_rate_limits(token_id, window_start);
ALTER TABLE scim_rate_limits ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_scim_rate_limits ON scim_rate_limits
    FOR ALL TO vault_app
    USING (tenant_id = current_tenant_id());

-- Trigger for updated_at
CREATE TRIGGER update_scim_rate_limits_updated_at 
    BEFORE UPDATE ON scim_rate_limits 
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

-- ============================================
-- Comments
-- ============================================

COMMENT ON TABLE scim_tokens IS 'SCIM Bearer tokens for IdP integration';
COMMENT ON TABLE scim_audit_logs IS 'Audit trail for all SCIM API operations';
COMMENT ON TABLE scim_group_members IS 'Junction table for SCIM group memberships';
COMMENT ON TABLE scim_settings IS 'Per-tenant SCIM configuration';
COMMENT ON TABLE scim_rate_limits IS 'Rate limiting for SCIM API calls';
