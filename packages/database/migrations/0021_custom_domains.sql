-- Custom Domains Table for White-Label Authentication
-- Allows tenants to use their own domains (e.g., auth.company.com) for authentication pages

-- Create enum type for custom domain status
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'custom_domain_status') THEN
        CREATE TYPE custom_domain_status AS ENUM ('pending', 'active', 'error', 'ssl_pending', 'ssl_failed');
    END IF;
END
$$;

-- Create enum type for SSL provider
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'ssl_provider') THEN
        CREATE TYPE ssl_provider AS ENUM ('lets_encrypt', 'custom', 'none');
    END IF;
END
$$;

-- Create the custom_domains table
CREATE TABLE IF NOT EXISTS custom_domains (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    domain VARCHAR(255) NOT NULL,
    status custom_domain_status NOT NULL DEFAULT 'pending',
    verification_token VARCHAR(255) NOT NULL,
    verified_at TIMESTAMPTZ,
    
    -- SSL/TLS certificate information
    ssl_provider ssl_provider NOT NULL DEFAULT 'lets_encrypt',
    certificate_path VARCHAR(500),
    private_key_path VARCHAR(500),
    certificate_chain_path VARCHAR(500),
    certificate_expires_at TIMESTAMPTZ,
    auto_ssl BOOLEAN NOT NULL DEFAULT true,
    force_https BOOLEAN NOT NULL DEFAULT true,
    
    -- DNS verification
    target_cname VARCHAR(255), -- Expected CNAME target (e.g., vault.example.com)
    last_dns_check_at TIMESTAMPTZ,
    last_dns_check_result BOOLEAN,
    last_dns_error TEXT,
    
    -- Branding settings for hosted pages
    brand_logo_url VARCHAR(500),
    brand_primary_color VARCHAR(7), -- Hex color like #FF5733
    brand_page_title VARCHAR(100),
    brand_favicon_url VARCHAR(500),
    
    -- Metadata
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID,
    
    -- Constraints
    CONSTRAINT unique_domain UNIQUE (domain),
    CONSTRAINT valid_domain_format CHECK (
        domain ~* '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$'
    ),
    CONSTRAINT verified_timestamp CHECK (
        (status NOT IN ('active') AND verified_at IS NULL) OR
        (status IN ('active') AND verified_at IS NOT NULL)
    )
);

-- Create indexes for efficient lookups
CREATE INDEX IF NOT EXISTS idx_custom_domains_tenant_id ON custom_domains(tenant_id);
CREATE INDEX IF NOT EXISTS idx_custom_domains_domain ON custom_domains(domain);
CREATE INDEX IF NOT EXISTS idx_custom_domains_status ON custom_domains(status);
CREATE INDEX IF NOT EXISTS idx_custom_domains_active_lookup ON custom_domains(domain, status) 
    WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_custom_domains_cert_expiry ON custom_domains(certificate_expires_at)
    WHERE auto_ssl = true AND status = 'active';

-- Create updated_at trigger
CREATE OR REPLACE FUNCTION update_custom_domains_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_custom_domains_updated_at ON custom_domains;
CREATE TRIGGER trigger_custom_domains_updated_at
    BEFORE UPDATE ON custom_domains
    FOR EACH ROW
    EXECUTE FUNCTION update_custom_domains_updated_at();

-- Add RLS policies
ALTER TABLE custom_domains ENABLE ROW LEVEL SECURITY;

-- Policy: Users can view custom domains for their tenant
DROP POLICY IF EXISTS custom_domains_select_tenant ON custom_domains;
CREATE POLICY custom_domains_select_tenant ON custom_domains
    FOR SELECT
    USING (tenant_id::text = current_setting('app.current_tenant_id', true));

-- Policy: Admins can manage custom domains for their tenant
DROP POLICY IF EXISTS custom_domains_manage_tenant ON custom_domains;
CREATE POLICY custom_domains_manage_tenant ON custom_domains
    FOR ALL
    USING (
        tenant_id::text = current_setting('app.current_tenant_id', true)
        AND current_setting('app.current_user_role', true) IN ('admin', 'owner', 'superadmin')
    );

-- Policy: Superadmins can view all custom domains
DROP POLICY IF EXISTS custom_domains_superadmin ON custom_domains;
CREATE POLICY custom_domains_superadmin ON custom_domains
    FOR ALL
    TO PUBLIC
    USING (current_setting('app.current_user_role', true) = 'superadmin');

-- Add audit logging trigger
CREATE OR REPLACE FUNCTION audit_custom_domains_changes()
RETURNS TRIGGER AS $$
DECLARE
    action_type TEXT;
    old_data JSONB;
    new_data JSONB;
BEGIN
    IF TG_OP = 'INSERT' THEN
        action_type := 'custom_domain.created';
        new_data := to_jsonb(NEW);
        old_data := null;
    ELSIF TG_OP = 'UPDATE' THEN
        action_type := 'custom_domain.updated';
        new_data := to_jsonb(NEW);
        old_data := to_jsonb(OLD);
    ELSIF TG_OP = 'DELETE' THEN
        action_type := 'custom_domain.deleted';
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
        'custom_domain',
        COALESCE(NEW.id::text, OLD.id::text),
        true,
        jsonb_build_object('old', old_data, 'new', new_data),
        NOW()
    );

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_audit_custom_domains ON custom_domains;
CREATE TRIGGER trigger_audit_custom_domains
    AFTER INSERT OR UPDATE OR DELETE ON custom_domains
    FOR EACH ROW
    EXECUTE FUNCTION audit_custom_domains_changes();

-- Create a function to get tenant by custom domain (for efficient lookups)
CREATE OR REPLACE FUNCTION get_tenant_by_custom_domain(domain_name TEXT)
RETURNS TABLE (
    tenant_id UUID,
    custom_domain_id UUID,
    force_https BOOLEAN,
    brand_logo_url VARCHAR,
    brand_primary_color VARCHAR,
    brand_page_title VARCHAR,
    brand_favicon_url VARCHAR
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        cd.tenant_id,
        cd.id AS custom_domain_id,
        cd.force_https,
        cd.brand_logo_url,
        cd.brand_primary_color,
        cd.brand_page_title,
        cd.brand_favicon_url
    FROM custom_domains cd
    WHERE cd.domain = domain_name
      AND cd.status = 'active';
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Grant permissions
GRANT SELECT, INSERT, UPDATE, DELETE ON custom_domains TO vault_app;
GRANT USAGE, SELECT ON SEQUENCE custom_domains_id_seq TO vault_app;
GRANT EXECUTE ON FUNCTION get_tenant_by_custom_domain(TEXT) TO vault_app;

-- Add comments for documentation
COMMENT ON TABLE custom_domains IS 'Stores custom domains for tenant white-label authentication';
COMMENT ON COLUMN custom_domains.domain IS 'Custom domain name (e.g., auth.company.com)';
COMMENT ON COLUMN custom_domains.status IS 'Domain status: pending, active, error, ssl_pending, ssl_failed';
COMMENT ON COLUMN custom_domains.verification_token IS 'Random token used for DNS verification';
COMMENT ON COLUMN custom_domains.target_cname IS 'Expected CNAME target that the custom domain should point to';
COMMENT ON COLUMN custom_domains.ssl_provider IS 'SSL certificate provider: lets_encrypt, custom, or none';
COMMENT ON COLUMN custom_domains.auto_ssl IS 'Whether to automatically manage SSL certificates via Lets Encrypt';
COMMENT ON COLUMN custom_domains.force_https IS 'Whether to redirect HTTP to HTTPS for this domain';
