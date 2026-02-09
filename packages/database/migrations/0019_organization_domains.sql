-- Organization Domains Table for B2B Auto-Enrollment
-- This table stores verified domains for organizations, enabling automatic
-- user enrollment based on email domain matching.

-- Create enum type for domain verification status
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'domain_status') THEN
        CREATE TYPE domain_status AS ENUM ('pending', 'verified', 'failed', 'expired');
    END IF;
END
$$;

-- Create enum type for verification method
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'verification_method') THEN
        CREATE TYPE verification_method AS ENUM ('dns', 'html_meta', 'file');
    END IF;
END
$$;

-- Create the organization_domains table
CREATE TABLE IF NOT EXISTS organization_domains (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    domain VARCHAR(255) NOT NULL,
    status domain_status NOT NULL DEFAULT 'pending',
    verification_method verification_method NOT NULL DEFAULT 'dns',
    verification_token VARCHAR(255) NOT NULL,
    verified_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    auto_enroll_enabled BOOLEAN NOT NULL DEFAULT true,
    default_role VARCHAR(50) NOT NULL DEFAULT 'member',
    dns_hostname VARCHAR(255),
    file_path VARCHAR(255),
    html_meta_content TEXT,
    
    -- Ensure domain is unique per organization
    CONSTRAINT unique_domain_per_org UNIQUE (organization_id, domain),
    -- Ensure verified_at is set when status is verified
    CONSTRAINT verified_timestamp CHECK (
        (status != 'verified' AND verified_at IS NULL) OR
        (status = 'verified' AND verified_at IS NOT NULL)
    )
);

-- Create indexes for efficient lookups
CREATE INDEX IF NOT EXISTS idx_org_domains_organization_id ON organization_domains(organization_id);
CREATE INDEX IF NOT EXISTS idx_org_domains_tenant_id ON organization_domains(tenant_id);
CREATE INDEX IF NOT EXISTS idx_org_domains_domain ON organization_domains(domain);
CREATE INDEX IF NOT EXISTS idx_org_domains_status ON organization_domains(status);
CREATE INDEX IF NOT EXISTS idx_org_domains_verified_lookup ON organization_domains(domain, status, auto_enroll_enabled) 
    WHERE status = 'verified' AND auto_enroll_enabled = true;

-- Create updated_at trigger
CREATE OR REPLACE FUNCTION update_org_domains_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_org_domains_updated_at ON organization_domains;
CREATE TRIGGER trigger_org_domains_updated_at
    BEFORE UPDATE ON organization_domains
    FOR EACH ROW
    EXECUTE FUNCTION update_org_domains_updated_at();

-- Add RLS policies
ALTER TABLE organization_domains ENABLE ROW LEVEL SECURITY;

-- Policy: Users can view domains for their tenant
DROP POLICY IF EXISTS org_domains_select_tenant ON organization_domains;
CREATE POLICY org_domains_select_tenant ON organization_domains
    FOR SELECT
    USING (tenant_id::text = current_setting('app.current_tenant_id', true));

-- Policy: Admins can manage domains for their tenant
DROP POLICY IF EXISTS org_domains_manage_tenant ON organization_domains;
CREATE POLICY org_domains_manage_tenant ON organization_domains
    FOR ALL
    USING (
        tenant_id::text = current_setting('app.current_tenant_id', true)
        AND current_setting('app.current_user_role', true) IN ('admin', 'owner', 'superadmin')
    );

-- Policy: Superadmins can view all domains
DROP POLICY IF EXISTS org_domains_superadmin ON organization_domains;
CREATE POLICY org_domains_superadmin ON organization_domains
    FOR ALL
    TO PUBLIC
    USING (current_setting('app.current_user_role', true) = 'superadmin');

-- Add audit logging trigger
CREATE OR REPLACE FUNCTION audit_org_domains_changes()
RETURNS TRIGGER AS $$
DECLARE
    action_type TEXT;
    old_data JSONB;
    new_data JSONB;
BEGIN
    IF TG_OP = 'INSERT' THEN
        action_type := 'domain.created';
        new_data := to_jsonb(NEW);
        old_data := null;
    ELSIF TG_OP = 'UPDATE' THEN
        action_type := 'domain.updated';
        new_data := to_jsonb(NEW);
        old_data := to_jsonb(OLD);
    ELSIF TG_OP = 'DELETE' THEN
        action_type := 'domain.deleted';
        new_data := null;
        old_data := to_jsonb(OLD);
        RETURN OLD;
    END IF;

    -- Insert into audit_logs
    INSERT INTO audit_logs (
        id, tenant_id, user_id, action, resource_type, resource_id,
        success, metadata, timestamp
    ) VALUES (
        gen_random_uuid(),
        COALESCE(NEW.tenant_id::text, OLD.tenant_id::text),
        current_setting('app.current_user_id', true),
        action_type,
        'domain',
        COALESCE(NEW.id::text, OLD.id::text),
        true,
        jsonb_build_object('old', old_data, 'new', new_data),
        NOW()
    );

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_audit_org_domains ON organization_domains;
CREATE TRIGGER trigger_audit_org_domains
    AFTER INSERT OR UPDATE OR DELETE ON organization_domains
    FOR EACH ROW
    EXECUTE FUNCTION audit_org_domains_changes();

-- Add organization setting for auto-enroll domains
DO $$
BEGIN
    -- Check if organizations table has auto_enroll_domains column
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'organizations' AND column_name = 'auto_enroll_domains'
    ) THEN
        ALTER TABLE organizations 
        ADD COLUMN auto_enroll_domains BOOLEAN NOT NULL DEFAULT false;
    END IF;
    
    -- Check if organizations table has auto_enroll_default_role column
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'organizations' AND column_name = 'auto_enroll_default_role'
    ) THEN
        ALTER TABLE organizations 
        ADD COLUMN auto_enroll_default_role VARCHAR(50) DEFAULT 'member';
    END IF;
END
$$;

-- Grant permissions
GRANT SELECT, INSERT, UPDATE, DELETE ON organization_domains TO vault_app;
GRANT USAGE, SELECT ON SEQUENCE organization_domains_id_seq TO vault_app;

-- Add comment for documentation
COMMENT ON TABLE organization_domains IS 'Stores verified domains for organizations, enabling B2B auto-enrollment based on email domain';
COMMENT ON COLUMN organization_domains.verification_token IS 'Random token used for domain verification via DNS TXT, HTML meta tag, or file upload';
COMMENT ON COLUMN organization_domains.auto_enroll_enabled IS 'When true, new users with matching email domains are automatically added to the organization';
COMMENT ON COLUMN organization_domains.default_role IS 'Role assigned to users who are auto-enrolled through this domain';
