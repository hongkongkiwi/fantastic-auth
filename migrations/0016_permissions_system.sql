-- RBAC++ Permission System Migration
-- Creates tables for fine-grained, resource-level permissions

-- ============================================
-- PERMISSIONS TABLE
-- Atomic actions that can be performed on resources
-- ============================================
CREATE TABLE IF NOT EXISTS permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    resource_type VARCHAR(50) NOT NULL, -- "document", "user", "organization", etc.
    action VARCHAR(50) NOT NULL, -- "read", "write", "delete", "admin", "manage"
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- Unique constraint: permission names are unique per tenant (or global)
    UNIQUE (tenant_id, name),
    -- Global permissions have NULL tenant_id
    CONSTRAINT chk_tenant_or_global CHECK (tenant_id IS NULL OR tenant_id IS NOT NULL)
);

-- Index for looking up permissions by name
CREATE INDEX IF NOT EXISTS idx_permissions_name ON permissions(name);
CREATE INDEX IF NOT EXISTS idx_permissions_tenant ON permissions(tenant_id);
CREATE INDEX IF NOT EXISTS idx_permissions_resource_type ON permissions(resource_type);

-- ============================================
-- ROLES TABLE
-- Collections of permissions that can be assigned to users
-- ============================================
CREATE TABLE IF NOT EXISTS roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    is_system_role BOOLEAN NOT NULL DEFAULT FALSE, -- true for superadmin, admin, member, viewer
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- Unique constraint: role names are unique per tenant (or global)
    UNIQUE (tenant_id, name)
);

-- Indexes for roles
CREATE INDEX IF NOT EXISTS idx_roles_name ON roles(name);
CREATE INDEX IF NOT EXISTS idx_roles_tenant ON roles(tenant_id);
CREATE INDEX IF NOT EXISTS idx_roles_system ON roles(is_system_role);

-- ============================================
-- ROLE_PERMISSIONS JUNCTION TABLE
-- Many-to-many relationship between roles and permissions
-- ============================================
CREATE TABLE IF NOT EXISTS role_permissions (
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    
    PRIMARY KEY (role_id, permission_id)
);

CREATE INDEX IF NOT EXISTS idx_role_permissions_permission ON role_permissions(permission_id);

-- ============================================
-- USER_ROLES TABLE
-- Assigns roles to users (tenant-level or org-specific)
-- ============================================
CREATE TABLE IF NOT EXISTS user_roles (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE, -- NULL for tenant-level roles
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    assigned_by UUID REFERENCES users(id) ON DELETE SET NULL,
    
    -- Unique constraint: one role assignment per (user, role, org) combination
    PRIMARY KEY (user_id, role_id, COALESCE(organization_id, '00000000-0000-0000-0000-000000000000'))
);

CREATE INDEX IF NOT EXISTS idx_user_roles_user ON user_roles(user_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_role ON user_roles(role_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_org ON user_roles(organization_id);

-- ============================================
-- RESOURCE_PERMISSIONS TABLE
-- Resource-level permission grants (e.g., "user X can admin document Y")
-- ============================================
CREATE TABLE IF NOT EXISTS resource_permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    resource_type VARCHAR(50) NOT NULL, -- "document", "folder", etc.
    resource_id VARCHAR(255) NOT NULL, -- specific resource identifier
    granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    granted_by UUID REFERENCES users(id) ON DELETE SET NULL,
    expires_at TIMESTAMPTZ, -- NULL for non-expiring permissions
    
    -- Unique constraint: one permission grant per (user, permission, resource) combination
    UNIQUE (user_id, permission_id, resource_type, resource_id)
);

CREATE INDEX IF NOT EXISTS idx_resource_permissions_user ON resource_permissions(user_id);
CREATE INDEX IF NOT EXISTS idx_resource_permissions_resource ON resource_permissions(resource_type, resource_id);
CREATE INDEX IF NOT EXISTS idx_resource_permissions_expires ON resource_permissions(expires_at) 
    WHERE expires_at IS NOT NULL;

-- ============================================
-- RLS POLICIES FOR PERMISSION TABLES
-- ============================================

-- Enable RLS on permission tables
ALTER TABLE permissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE role_permissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE resource_permissions ENABLE ROW LEVEL SECURITY;

-- Policies for permissions table
CREATE POLICY tenant_isolation_permissions ON permissions
    USING (tenant_id IS NULL OR tenant_id = current_setting('app.current_tenant_id')::UUID);

-- Policies for roles table
CREATE POLICY tenant_isolation_roles ON roles
    USING (tenant_id IS NULL OR tenant_id = current_setting('app.current_tenant_id')::UUID);

-- Policies for role_permissions (through roles)
CREATE POLICY tenant_isolation_role_permissions ON role_permissions
    USING (
        EXISTS (
            SELECT 1 FROM roles r 
            WHERE r.id = role_permissions.role_id 
            AND (r.tenant_id IS NULL OR r.tenant_id = current_setting('app.current_tenant_id')::UUID)
        )
    );

-- Policies for user_roles (through roles)
CREATE POLICY tenant_isolation_user_roles ON user_roles
    USING (
        EXISTS (
            SELECT 1 FROM roles r 
            WHERE r.id = user_roles.role_id 
            AND (r.tenant_id IS NULL OR r.tenant_id = current_setting('app.current_tenant_id')::UUID)
        )
    );

-- Policies for resource_permissions (through users)
CREATE POLICY tenant_isolation_resource_permissions ON resource_permissions
    USING (
        EXISTS (
            SELECT 1 FROM users u 
            WHERE u.id = resource_permissions.user_id 
            AND u.tenant_id = current_setting('app.current_tenant_id')::UUID
        )
    );

-- ============================================
-- HELPER FUNCTIONS
-- ============================================

-- Function to get all permissions for a user
CREATE OR REPLACE FUNCTION get_user_permissions(p_user_id UUID)
RETURNS TABLE(permission_name VARCHAR) AS $$
BEGIN
    RETURN QUERY
    SELECT DISTINCT p.name
    FROM permissions p
    INNER JOIN role_permissions rp ON p.id = rp.permission_id
    INNER JOIN user_roles ur ON rp.role_id = ur.role_id
    WHERE ur.user_id = p_user_id
    UNION
    SELECT DISTINCT 
        CASE 
            WHEN rp.resource_id IS NOT NULL THEN 
                p.resource_type || ':' || rp.resource_id || ':' || p.action
            ELSE 
                p.name
        END::VARCHAR
    FROM resource_permissions rp
    INNER JOIN permissions p ON rp.permission_id = p.id
    WHERE rp.user_id = p_user_id
    AND (rp.expires_at IS NULL OR rp.expires_at > NOW());
END;
$$ LANGUAGE plpgsql;

-- Function to check if a user has a specific permission
CREATE OR REPLACE FUNCTION user_has_permission(
    p_user_id UUID,
    p_permission VARCHAR
)
RETURNS BOOLEAN AS $$
DECLARE
    v_has_permission BOOLEAN;
    v_is_superadmin BOOLEAN;
BEGIN
    -- Check if user is superadmin (bypass all)
    SELECT EXISTS(
        SELECT 1 FROM user_roles ur
        INNER JOIN roles r ON ur.role_id = r.id
        WHERE ur.user_id = p_user_id AND r.name = 'superadmin'
    ) INTO v_is_superadmin;
    
    IF v_is_superadmin THEN
        RETURN TRUE;
    END IF;
    
    -- Check for direct permission match
    SELECT EXISTS(
        SELECT 1 FROM get_user_permissions(p_user_id) WHERE permission_name = p_permission
    ) INTO v_has_permission;
    
    IF v_has_permission THEN
        RETURN TRUE;
    END IF;
    
    -- Check for wildcard match (e.g., "document:*" matches "document:read")
    RETURN EXISTS(
        SELECT 1 FROM get_user_permissions(p_user_id) 
        WHERE permission_name LIKE REPLACE(p_permission, ':', ':%') 
           OR (p_permission LIKE REPLACE(permission_name, '*', '%') AND permission_name LIKE '%:*')
    );
END;
$$ LANGUAGE plpgsql;

-- Function to get user roles
CREATE OR REPLACE FUNCTION get_user_roles(p_user_id UUID)
RETURNS TABLE(role_name VARCHAR) AS $$
BEGIN
    RETURN QUERY
    SELECT DISTINCT r.name
    FROM roles r
    INNER JOIN user_roles ur ON r.id = ur.role_id
    WHERE ur.user_id = p_user_id;
END;
$$ LANGUAGE plpgsql;

-- ============================================
-- TRIGGER FOR UPDATING updated_at
-- ============================================
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_roles_updated_at
    BEFORE UPDATE ON roles
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ============================================
-- DEFAULT PERMISSIONS (INSERTED BY APPLICATION)
-- ============================================
-- The application should call the /api/v1/admin/permissions/initialize
-- endpoint to populate these. System roles and permissions are tenant-agnostic.
