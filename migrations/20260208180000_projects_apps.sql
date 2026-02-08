-- Projects + Applications (B2B core)

-- ============================================
-- Enums
-- ============================================
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'project_status') THEN
        CREATE TYPE project_status AS ENUM ('active', 'inactive', 'archived');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'application_type') THEN
        CREATE TYPE application_type AS ENUM ('oidc', 'saml', 'api');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'application_status') THEN
        CREATE TYPE application_status AS ENUM ('active', 'inactive');
    END IF;
END $$;

-- ============================================
-- Helper functions for org membership
-- ============================================
CREATE OR REPLACE FUNCTION is_org_member(p_org_id UUID)
RETURNS BOOLEAN AS $$
BEGIN
    RETURN EXISTS (
        SELECT 1
        FROM organization_members m
        WHERE m.organization_id = p_org_id
          AND m.tenant_id = current_setting('app.current_tenant_id', true)::UUID
          AND m.user_id = current_setting('app.current_user_id', true)::UUID
          AND m.status = 'active'
    );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public;

CREATE OR REPLACE FUNCTION is_org_admin(p_org_id UUID)
RETURNS BOOLEAN AS $$
BEGIN
    RETURN EXISTS (
        SELECT 1
        FROM organization_members m
        WHERE m.organization_id = p_org_id
          AND m.tenant_id = current_setting('app.current_tenant_id', true)::UUID
          AND m.user_id = current_setting('app.current_user_id', true)::UUID
          AND m.status = 'active'
          AND m.role IN ('owner', 'admin')
    );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public;

REVOKE ALL ON FUNCTION is_org_member(UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION is_org_admin(UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION is_org_member(UUID) TO vault_app, vault_service;
GRANT EXECUTE ON FUNCTION is_org_admin(UUID) TO vault_app, vault_service;

-- ============================================
-- Projects
-- ============================================
CREATE TABLE IF NOT EXISTS projects (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(255) NOT NULL,
    description TEXT,
    status project_status NOT NULL DEFAULT 'active',
    metadata JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ,

    UNIQUE(organization_id, slug)
);

CREATE INDEX IF NOT EXISTS idx_projects_tenant ON projects(tenant_id);
CREATE INDEX IF NOT EXISTS idx_projects_org ON projects(organization_id);
CREATE INDEX IF NOT EXISTS idx_projects_status ON projects(status);

-- ============================================
-- Applications
-- ============================================
CREATE TABLE IF NOT EXISTS applications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    app_type application_type NOT NULL,
    status application_status NOT NULL DEFAULT 'active',
    settings JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE(project_id, name)
);

CREATE INDEX IF NOT EXISTS idx_applications_tenant ON applications(tenant_id);
CREATE INDEX IF NOT EXISTS idx_applications_project ON applications(project_id);
CREATE INDEX IF NOT EXISTS idx_applications_type ON applications(app_type);

-- ============================================
-- Project Roles
-- ============================================
CREATE TABLE IF NOT EXISTS project_roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    permissions JSONB NOT NULL DEFAULT '[]',
    is_system_role BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE(project_id, name)
);

CREATE INDEX IF NOT EXISTS idx_project_roles_project ON project_roles(project_id);

-- ============================================
-- Project Role Assignments
-- ============================================
CREATE TABLE IF NOT EXISTS project_role_assignments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES project_roles(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    assigned_by UUID REFERENCES users(id) ON DELETE SET NULL,

    UNIQUE(project_id, role_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_project_role_assignments_project ON project_role_assignments(project_id);
CREATE INDEX IF NOT EXISTS idx_project_role_assignments_user ON project_role_assignments(user_id);

-- ============================================
-- Project Grants (cross-org access)
-- ============================================
CREATE TABLE IF NOT EXISTS project_grants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    granted_organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    default_role_id UUID REFERENCES project_roles(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE(project_id, granted_organization_id)
);

CREATE INDEX IF NOT EXISTS idx_project_grants_project ON project_grants(project_id);
CREATE INDEX IF NOT EXISTS idx_project_grants_org ON project_grants(granted_organization_id);

-- ============================================
-- Link existing auth tables to applications
-- ============================================
ALTER TABLE oauth_clients ADD COLUMN IF NOT EXISTS application_id UUID REFERENCES applications(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_oauth_clients_app ON oauth_clients(application_id);

ALTER TABLE saml_connections ADD COLUMN IF NOT EXISTS application_id UUID REFERENCES applications(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_saml_connections_app ON saml_connections(application_id);

ALTER TABLE service_accounts ADD COLUMN IF NOT EXISTS application_id UUID REFERENCES applications(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_service_accounts_app ON service_accounts(application_id);

-- ============================================
-- RLS
-- ============================================
ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE applications ENABLE ROW LEVEL SECURITY;
ALTER TABLE project_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE project_role_assignments ENABLE ROW LEVEL SECURITY;
ALTER TABLE project_grants ENABLE ROW LEVEL SECURITY;

-- Enforce RLS for table owners
ALTER TABLE projects FORCE ROW LEVEL SECURITY;
ALTER TABLE applications FORCE ROW LEVEL SECURITY;
ALTER TABLE project_roles FORCE ROW LEVEL SECURITY;
ALTER TABLE project_role_assignments FORCE ROW LEVEL SECURITY;
ALTER TABLE project_grants FORCE ROW LEVEL SECURITY;

-- Projects policies
DROP POLICY IF EXISTS projects_select ON projects;
CREATE POLICY projects_select ON projects
    FOR SELECT TO vault_app
    USING (
        tenant_id = current_tenant_id()
        AND (is_admin() OR is_org_member(organization_id))
    );

DROP POLICY IF EXISTS projects_insert ON projects;
CREATE POLICY projects_insert ON projects
    FOR INSERT TO vault_app
    WITH CHECK (
        tenant_id = current_tenant_id()
        AND (is_admin() OR is_org_admin(organization_id))
    );

DROP POLICY IF EXISTS projects_update ON projects;
CREATE POLICY projects_update ON projects
    FOR UPDATE TO vault_app
    USING (
        tenant_id = current_tenant_id()
        AND (is_admin() OR is_org_admin(organization_id))
    )
    WITH CHECK (tenant_id = current_tenant_id());

DROP POLICY IF EXISTS projects_delete ON projects;
CREATE POLICY projects_delete ON projects
    FOR DELETE TO vault_app
    USING (
        tenant_id = current_tenant_id()
        AND (is_admin() OR is_org_admin(organization_id))
    );

-- Applications policies
DROP POLICY IF EXISTS applications_select ON applications;
CREATE POLICY applications_select ON applications
    FOR SELECT TO vault_app
    USING (
        tenant_id = current_tenant_id()
        AND (is_admin() OR is_org_member(organization_id))
    );

DROP POLICY IF EXISTS applications_insert ON applications;
CREATE POLICY applications_insert ON applications
    FOR INSERT TO vault_app
    WITH CHECK (
        tenant_id = current_tenant_id()
        AND (is_admin() OR is_org_admin(organization_id))
    );

DROP POLICY IF EXISTS applications_update ON applications;
CREATE POLICY applications_update ON applications
    FOR UPDATE TO vault_app
    USING (
        tenant_id = current_tenant_id()
        AND (is_admin() OR is_org_admin(organization_id))
    )
    WITH CHECK (tenant_id = current_tenant_id());

DROP POLICY IF EXISTS applications_delete ON applications;
CREATE POLICY applications_delete ON applications
    FOR DELETE TO vault_app
    USING (
        tenant_id = current_tenant_id()
        AND (is_admin() OR is_org_admin(organization_id))
    );

-- Project roles policies
DROP POLICY IF EXISTS project_roles_select ON project_roles;
CREATE POLICY project_roles_select ON project_roles
    FOR SELECT TO vault_app
    USING (
        tenant_id = current_tenant_id()
        AND EXISTS (
            SELECT 1 FROM projects p
            WHERE p.id = project_roles.project_id
              AND (is_admin() OR is_org_member(p.organization_id))
        )
    );

DROP POLICY IF EXISTS project_roles_write ON project_roles;
CREATE POLICY project_roles_write ON project_roles
    FOR INSERT, UPDATE, DELETE TO vault_app
    USING (
        tenant_id = current_tenant_id()
        AND EXISTS (
            SELECT 1 FROM projects p
            WHERE p.id = project_roles.project_id
              AND (is_admin() OR is_org_admin(p.organization_id))
        )
    )
    WITH CHECK (tenant_id = current_tenant_id());

-- Project role assignments policies
DROP POLICY IF EXISTS project_role_assignments_select ON project_role_assignments;
CREATE POLICY project_role_assignments_select ON project_role_assignments
    FOR SELECT TO vault_app
    USING (
        tenant_id = current_tenant_id()
        AND (
            user_id = current_setting('app.current_user_id', true)::UUID
            OR EXISTS (
                SELECT 1 FROM projects p
                WHERE p.id = project_role_assignments.project_id
                  AND (is_admin() OR is_org_admin(p.organization_id))
            )
        )
    );

DROP POLICY IF EXISTS project_role_assignments_write ON project_role_assignments;
CREATE POLICY project_role_assignments_write ON project_role_assignments
    FOR INSERT, UPDATE, DELETE TO vault_app
    USING (
        tenant_id = current_tenant_id()
        AND EXISTS (
            SELECT 1 FROM projects p
            WHERE p.id = project_role_assignments.project_id
              AND (is_admin() OR is_org_admin(p.organization_id))
        )
    )
    WITH CHECK (tenant_id = current_tenant_id());

-- Project grants policies
DROP POLICY IF EXISTS project_grants_select ON project_grants;
CREATE POLICY project_grants_select ON project_grants
    FOR SELECT TO vault_app
    USING (
        tenant_id = current_tenant_id()
        AND (
            EXISTS (
                SELECT 1 FROM projects p
                WHERE p.id = project_grants.project_id
                  AND (is_admin() OR is_org_admin(p.organization_id))
            )
            OR is_org_member(granted_organization_id)
        )
    );

DROP POLICY IF EXISTS project_grants_write ON project_grants;
CREATE POLICY project_grants_write ON project_grants
    FOR INSERT, UPDATE, DELETE TO vault_app
    USING (
        tenant_id = current_tenant_id()
        AND EXISTS (
            SELECT 1 FROM projects p
            WHERE p.id = project_grants.project_id
              AND (is_admin() OR is_org_admin(p.organization_id))
        )
    )
    WITH CHECK (tenant_id = current_tenant_id());

-- ============================================
-- Triggers
-- ============================================
CREATE TRIGGER update_projects_updated_at
    BEFORE UPDATE ON projects
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_applications_updated_at
    BEFORE UPDATE ON applications
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_project_roles_updated_at
    BEFORE UPDATE ON project_roles
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================
-- Comments
-- ============================================
COMMENT ON TABLE projects IS 'Projects group applications within an organization';
COMMENT ON TABLE applications IS 'Applications are auth clients within a project (OIDC/SAML/API)';
COMMENT ON TABLE project_roles IS 'Project-scoped roles and permissions';
COMMENT ON TABLE project_role_assignments IS 'Assignments of project roles to users';
COMMENT ON TABLE project_grants IS 'Cross-organization grants for projects';

-- ============================================
-- Grants
-- ============================================
GRANT SELECT, INSERT, UPDATE, DELETE ON projects TO vault_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON applications TO vault_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON project_roles TO vault_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON project_role_assignments TO vault_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON project_grants TO vault_app;

GRANT SELECT ON projects TO vault_readonly;
GRANT SELECT ON applications TO vault_readonly;
GRANT SELECT ON project_roles TO vault_readonly;
GRANT SELECT ON project_role_assignments TO vault_readonly;
GRANT SELECT ON project_grants TO vault_readonly;
