-- LDAP/Active Directory Integration
-- Tables for LDAP connections, user mappings, and sync logs

-- ============================================
-- LDAP Connections Table
-- ============================================

CREATE TABLE IF NOT EXISTS ldap_connections (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    
    -- Connection settings
    url VARCHAR(500) NOT NULL,                    -- ldaps://ad.company.com:636
    bind_dn VARCHAR(500) NOT NULL,                -- CN=admin,DC=company,DC=com
    bind_password_encrypted TEXT NOT NULL,        -- Encrypted bind password
    base_dn VARCHAR(500) NOT NULL,                -- DC=company,DC=com
    
    -- Search configuration
    user_search_base VARCHAR(500),                -- OU=Users,DC=company,DC=com
    user_search_filter VARCHAR(500) NOT NULL DEFAULT '(objectClass=user)',
    group_search_base VARCHAR(500),               -- OU=Groups,DC=company,DC=com
    group_search_filter VARCHAR(500) NOT NULL DEFAULT '(objectClass=group)',
    
    -- Attribute mappings (JSONB for flexibility)
    user_attribute_mappings JSONB NOT NULL DEFAULT '{
        "email": "mail",
        "username": "sAMAccountName",
        "first_name": "givenName",
        "last_name": "sn",
        "display_name": "displayName",
        "phone": "telephoneNumber",
        "department": "department",
        "title": "title",
        "employee_id": "employeeID",
        "object_guid": "objectGUID"
    }',
    
    -- Sync configuration
    sync_interval_minutes INTEGER NOT NULL DEFAULT 60,
    last_sync_at TIMESTAMPTZ,
    last_sync_status VARCHAR(50),                 -- success, partial, failed
    last_sync_error TEXT,
    next_sync_at TIMESTAMPTZ,
    
    -- JIT provisioning settings
    jit_provisioning_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    jit_default_role org_role NOT NULL DEFAULT 'member',
    jit_default_status user_status NOT NULL DEFAULT 'active',
    jit_organization_id UUID REFERENCES organizations(id) ON DELETE SET NULL,
    
    -- Group membership sync
    group_sync_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    group_mappings JSONB NOT NULL DEFAULT '[]',   -- [{"ldap_group": "CN=Admins", "vault_role": "admin"}]
    
    -- Advanced settings
    tls_verify_cert BOOLEAN NOT NULL DEFAULT TRUE,
    tls_ca_cert TEXT,                             -- Custom CA certificate
    connection_timeout_secs INTEGER NOT NULL DEFAULT 10,
    search_timeout_secs INTEGER NOT NULL DEFAULT 30,
    page_size INTEGER NOT NULL DEFAULT 1000,      -- For LDAP pagination
    
    -- Status tracking
    connection_status VARCHAR(50) NOT NULL DEFAULT 'pending', -- pending, connected, error
    connection_tested_at TIMESTAMPTZ,
    connection_error TEXT,
    
    metadata JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID REFERENCES users(id),
    
    UNIQUE(tenant_id, name)
);

-- ============================================
-- LDAP Sync Logs Table
-- ============================================

CREATE TABLE IF NOT EXISTS ldap_sync_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    connection_id UUID NOT NULL REFERENCES ldap_connections(id) ON DELETE CASCADE,
    
    -- Sync run details
    sync_type VARCHAR(50) NOT NULL,               -- full, incremental, test
    status VARCHAR(50) NOT NULL,                  -- running, success, partial, failed
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    
    -- Statistics
    users_found INTEGER NOT NULL DEFAULT 0,
    users_created INTEGER NOT NULL DEFAULT 0,
    users_updated INTEGER NOT NULL DEFAULT 0,
    users_disabled INTEGER NOT NULL DEFAULT 0,
    users_unchanged INTEGER NOT NULL DEFAULT 0,
    users_failed INTEGER NOT NULL DEFAULT 0,
    
    groups_found INTEGER NOT NULL DEFAULT 0,
    groups_created INTEGER NOT NULL DEFAULT 0,
    groups_updated INTEGER NOT NULL DEFAULT 0,
    groups_failed INTEGER NOT NULL DEFAULT 0,
    
    -- Error details
    error_message TEXT,
    error_details JSONB,
    
    -- Detailed log entries (stored as JSONB array)
    log_entries JSONB NOT NULL DEFAULT '[]',
    
    -- Performance metrics
    duration_ms INTEGER,
    
    -- Triggered by (user ID or 'system' for scheduled)
    triggered_by VARCHAR(255) NOT NULL DEFAULT 'system',
    
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================
-- LDAP User Mappings Table
-- Tracks which Vault users are linked to LDAP entries
-- ============================================

CREATE TABLE IF NOT EXISTS ldap_user_mappings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    connection_id UUID NOT NULL REFERENCES ldap_connections(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    
    -- LDAP identifiers
    ldap_dn VARCHAR(500) NOT NULL,                -- Full distinguished name
    ldap_guid VARCHAR(255),                       -- Object GUID (binary or string)
    ldap_object_sid VARCHAR(255),                 -- Windows SID
    
    -- Sync tracking
    last_synced_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    sync_hash VARCHAR(64),                        -- Hash of LDAP attributes for change detection
    
    -- Deprovision tracking
    deprovisioned_at TIMESTAMPTZ,
    deprovision_reason VARCHAR(255),
    
    metadata JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    UNIQUE(tenant_id, connection_id, user_id),
    UNIQUE(tenant_id, connection_id, ldap_dn)
);

-- ============================================
-- LDAP Group Mappings Table
-- ============================================

CREATE TABLE IF NOT EXISTS ldap_group_mappings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    connection_id UUID NOT NULL REFERENCES ldap_connections(id) ON DELETE CASCADE,
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    
    -- LDAP identifiers
    ldap_dn VARCHAR(500) NOT NULL,
    ldap_guid VARCHAR(255),
    ldap_name VARCHAR(255) NOT NULL,
    
    -- Vault role mapping
    vault_role org_role,
    custom_permissions JSONB DEFAULT '[]',
    
    -- Sync tracking
    last_synced_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    member_count INTEGER NOT NULL DEFAULT 0,
    
    metadata JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    UNIQUE(tenant_id, connection_id, ldap_dn)
);

-- ============================================
-- RLS Policies
-- ============================================

ALTER TABLE ldap_connections ENABLE ROW LEVEL SECURITY;
ALTER TABLE ldap_sync_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE ldap_user_mappings ENABLE ROW LEVEL SECURITY;
ALTER TABLE ldap_group_mappings ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_ldap_connections ON ldap_connections
    FOR ALL TO vault_app
    USING (tenant_id = current_tenant_id());

CREATE POLICY tenant_isolation_ldap_sync_logs ON ldap_sync_logs
    FOR ALL TO vault_app
    USING (tenant_id = current_tenant_id());

CREATE POLICY tenant_isolation_ldap_user_mappings ON ldap_user_mappings
    FOR ALL TO vault_app
    USING (tenant_id = current_tenant_id());

CREATE POLICY tenant_isolation_ldap_group_mappings ON ldap_group_mappings
    FOR ALL TO vault_app
    USING (tenant_id = current_tenant_id());

-- ============================================
-- Indexes
-- ============================================

CREATE INDEX idx_ldap_connections_tenant ON ldap_connections(tenant_id);
CREATE INDEX idx_ldap_connections_status ON ldap_connections(connection_status) WHERE enabled = TRUE;
CREATE INDEX idx_ldap_connections_next_sync ON ldap_connections(next_sync_at) WHERE enabled = TRUE;

CREATE INDEX idx_ldap_sync_logs_connection ON ldap_sync_logs(connection_id, started_at DESC);
CREATE INDEX idx_ldap_sync_logs_tenant_started ON ldap_sync_logs(tenant_id, started_at DESC);
CREATE INDEX idx_ldap_sync_logs_status ON ldap_sync_logs(status) WHERE status = 'running';

CREATE INDEX idx_ldap_user_mappings_connection ON ldap_user_mappings(connection_id);
CREATE INDEX idx_ldap_user_mappings_user ON ldap_user_mappings(user_id);
CREATE INDEX idx_ldap_user_mappings_guid ON ldap_user_mappings(ldap_guid);

CREATE INDEX idx_ldap_group_mappings_connection ON ldap_group_mappings(connection_id);
CREATE INDEX idx_ldap_group_mappings_org ON ldap_group_mappings(organization_id);

-- ============================================
-- Triggers
-- ============================================

CREATE TRIGGER update_ldap_connections_updated_at BEFORE UPDATE ON ldap_connections
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_ldap_user_mappings_updated_at BEFORE UPDATE ON ldap_user_mappings
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_ldap_group_mappings_updated_at BEFORE UPDATE ON ldap_group_mappings
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================
-- Comments
-- ============================================

COMMENT ON TABLE ldap_connections IS 'LDAP/Active Directory server configurations';
COMMENT ON COLUMN ldap_connections.bind_password_encrypted IS 'AES-256 encrypted bind password';
COMMENT ON COLUMN ldap_connections.user_attribute_mappings IS 'JSON mapping of LDAP attributes to Vault user fields';
COMMENT ON COLUMN ldap_connections.jit_provisioning_enabled IS 'Allow automatic user creation from LDAP on first login';

COMMENT ON TABLE ldap_sync_logs IS 'Audit log for LDAP synchronization runs';
COMMENT ON TABLE ldap_user_mappings IS 'Links Vault users to their LDAP directory entries';
COMMENT ON TABLE ldap_group_mappings IS 'Links LDAP groups to Vault roles/organizations';
