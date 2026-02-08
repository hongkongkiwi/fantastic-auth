-- Consent Management Migration
-- GDPR/CCPA compliance tables

-- Enable required extensions (if not already enabled)
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ============================================
-- Custom Types
-- ============================================

CREATE TYPE consent_type AS ENUM (
    'terms_of_service',
    'privacy_policy', 
    'marketing',
    'analytics',
    'cookies',
    'data_sharing',
    'advertising'
);

CREATE TYPE data_export_status AS ENUM (
    'pending',
    'processing',
    'ready',
    'downloaded',
    'expired',
    'failed'
);

CREATE TYPE deletion_status AS ENUM (
    'pending',
    'cancelled',
    'processing',
    'completed',
    'failed'
);

-- ============================================
-- Consent Versions Table
-- ============================================

CREATE TABLE consent_versions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    consent_type consent_type NOT NULL,
    version VARCHAR(20) NOT NULL,
    title VARCHAR(255) NOT NULL,
    content TEXT NOT NULL,
    summary TEXT,
    effective_date TIMESTAMPTZ NOT NULL,
    url TEXT,
    is_current BOOLEAN NOT NULL DEFAULT FALSE,
    required BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- Ensure version uniqueness within tenant and type
    UNIQUE(tenant_id, consent_type, version)
);

-- ============================================
-- User Consents Table
-- ============================================

CREATE TABLE user_consents (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    consent_version_id UUID NOT NULL REFERENCES consent_versions(id) ON DELETE CASCADE,
    granted BOOLEAN NOT NULL,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ip_address INET,
    user_agent TEXT,
    jurisdiction VARCHAR(50),
    withdrawn_at TIMESTAMPTZ,
    
    -- Ensure one consent record per user per version
    UNIQUE(user_id, consent_version_id)
);

-- ============================================
-- Data Export Requests Table (GDPR Article 20)
-- ============================================

CREATE TABLE data_export_requests (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    status data_export_status NOT NULL DEFAULT 'pending',
    requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    download_url TEXT,
    expires_at TIMESTAMPTZ,
    error_message TEXT,
    
    -- Ensure one pending export per user
    CONSTRAINT one_pending_export_per_user 
        EXCLUDE (user_id WITH =) 
        WHERE (status IN ('pending', 'processing'))
);

-- ============================================
-- Deletion Requests Table (GDPR Article 17)
-- ============================================

CREATE TABLE deletion_requests (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    status deletion_status NOT NULL DEFAULT 'pending',
    requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    scheduled_deletion_at TIMESTAMPTZ NOT NULL,
    deleted_at TIMESTAMPTZ,
    cancellation_token VARCHAR(255) NOT NULL UNIQUE,
    reason TEXT,
    error_message TEXT,
    
    -- Ensure one active deletion request per user
    CONSTRAINT one_active_deletion_per_user 
        EXCLUDE (user_id WITH =) 
        WHERE (status IN ('pending', 'processing'))
);

-- ============================================
-- Tenant Consent Configuration Table
-- ============================================

CREATE TABLE tenant_consent_configs (
    tenant_id UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    deletion_grace_period_days INTEGER NOT NULL DEFAULT 30,
    export_retention_days INTEGER NOT NULL DEFAULT 7,
    require_explicit_consent BOOLEAN NOT NULL DEFAULT TRUE,
    default_jurisdiction VARCHAR(50) NOT NULL DEFAULT 'GDPR',
    cookie_config JSONB NOT NULL DEFAULT '{}',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================
-- Indexes for Performance
-- ============================================

-- Consent version indexes
CREATE INDEX idx_consent_versions_tenant ON consent_versions(tenant_id);
CREATE INDEX idx_consent_versions_type_current ON consent_versions(tenant_id, consent_type, is_current);
CREATE INDEX idx_consent_versions_effective ON consent_versions(effective_date);

-- User consent indexes
CREATE INDEX idx_user_consents_user ON user_consents(user_id);
CREATE INDEX idx_user_consents_version ON user_consents(consent_version_id);
CREATE INDEX idx_user_consents_granted_at ON user_consents(granted_at);

-- Data export indexes
CREATE INDEX idx_data_export_user ON data_export_requests(user_id);
CREATE INDEX idx_data_export_status ON data_export_requests(status);
CREATE INDEX idx_data_export_expires ON data_export_requests(expires_at) 
    WHERE status = 'ready';

-- Deletion request indexes
CREATE INDEX idx_deletion_user ON deletion_requests(user_id);
CREATE INDEX idx_deletion_status ON deletion_requests(status);
CREATE INDEX idx_deletion_scheduled ON deletion_requests(scheduled_deletion_at) 
    WHERE status = 'pending';
CREATE INDEX idx_deletion_token ON deletion_requests(cancellation_token);

-- ============================================
-- Row-Level Security Policies
-- ============================================

ALTER TABLE consent_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_consents ENABLE ROW LEVEL SECURITY;
ALTER TABLE data_export_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE deletion_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_consent_configs ENABLE ROW LEVEL SECURITY;

-- Consent versions - readable by all in tenant, writable by admin
CREATE POLICY tenant_isolation_consent_versions ON consent_versions
    FOR ALL
    TO vault_app
    USING (tenant_id = current_tenant_id());

-- User consents - users see own, admins see all
CREATE POLICY own_consents ON user_consents
    FOR ALL
    TO vault_app
    USING (
        user_id = current_setting('app.current_user_id', TRUE)::UUID 
        OR is_admin()
    );

-- Data exports - users see own, admins see all
CREATE POLICY own_exports ON data_export_requests
    FOR ALL
    TO vault_app
    USING (
        user_id = current_setting('app.current_user_id', TRUE)::UUID 
        OR is_admin()
    );

-- Deletion requests - users see own, admins see all
CREATE POLICY own_deletions ON deletion_requests
    FOR ALL
    TO vault_app
    USING (
        user_id = current_setting('app.current_user_id', TRUE)::UUID 
        OR is_admin()
    );

-- Tenant config - readable by all, writable by admin
CREATE POLICY tenant_isolation_configs ON tenant_consent_configs
    FOR ALL
    TO vault_app
    USING (tenant_id = current_tenant_id());

-- ============================================
-- Triggers
-- ============================================

-- Update tenant_consent_configs updated_at
CREATE TRIGGER update_tenant_consent_configs_updated_at 
    BEFORE UPDATE ON tenant_consent_configs 
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

-- ============================================
-- Views
-- ============================================

-- User consent summary view
CREATE VIEW user_consent_summary AS
SELECT 
    u.id as user_id,
    u.tenant_id,
    u.email,
    cv.consent_type,
    cv.version,
    cv.title,
    cv.required,
    uc.granted,
    uc.granted_at,
    uc.withdrawn_at,
    CASE 
        WHEN cv.required AND (uc.granted IS NULL OR uc.granted = FALSE) THEN 'missing_required'
        WHEN cv.is_current AND uc.granted IS NULL THEN 'pending'
        WHEN uc.granted = TRUE AND cv.is_current THEN 'current'
        WHEN uc.granted = TRUE AND NOT cv.is_current THEN 'outdated'
        WHEN uc.granted = FALSE THEN 'withdrawn'
        ELSE 'unknown'
    END as status
FROM users u
CROSS JOIN consent_versions cv
LEFT JOIN user_consents uc ON u.id = uc.user_id AND cv.id = uc.consent_version_id
WHERE cv.is_current = TRUE
  AND u.deleted_at IS NULL;

-- Pending consents view
CREATE VIEW pending_consents AS
SELECT *
FROM user_consent_summary
WHERE status = 'pending' OR status = 'missing_required';

-- Consent statistics view
CREATE VIEW consent_statistics AS
SELECT 
    cv.tenant_id,
    cv.id as version_id,
    cv.consent_type,
    cv.version,
    COUNT(DISTINCT u.id) as total_users,
    COUNT(DISTINCT CASE WHEN uc.granted = TRUE THEN uc.user_id END) as granted_count,
    COUNT(DISTINCT CASE WHEN uc.granted = FALSE AND uc.withdrawn_at IS NOT NULL THEN uc.user_id END) as withdrawn_count,
    COUNT(DISTINCT u.id) - COUNT(DISTINCT uc.user_id) as pending_count,
    CASE 
        WHEN COUNT(DISTINCT u.id) > 0 
        THEN ROUND(
            COUNT(DISTINCT CASE WHEN uc.granted = TRUE THEN uc.user_id END)::numeric 
            / COUNT(DISTINCT u.id)::numeric * 100, 
            2
        )
        ELSE 0
    END as consent_rate
FROM consent_versions cv
CROSS JOIN users u
LEFT JOIN user_consents uc ON cv.id = uc.consent_version_id AND u.id = uc.user_id
WHERE cv.is_current = TRUE
  AND u.deleted_at IS NULL
GROUP BY cv.tenant_id, cv.id, cv.consent_type, cv.version;

-- ============================================
-- Functions
-- ============================================

-- Function to check if user has consented to all required consents
CREATE OR REPLACE FUNCTION has_required_consents(p_user_id UUID, p_tenant_id UUID)
RETURNS BOOLEAN AS $$
DECLARE
    v_missing_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO v_missing_count
    FROM consent_versions cv
    LEFT JOIN user_consents uc ON cv.id = uc.consent_version_id AND uc.user_id = p_user_id
    WHERE cv.tenant_id = p_tenant_id
      AND cv.is_current = TRUE
      AND cv.required = TRUE
      AND (uc.granted IS NULL OR uc.granted = FALSE);
    
    RETURN v_missing_count = 0;
END;
$$ LANGUAGE plpgsql;

-- Function to get pending consents for a user
CREATE OR REPLACE FUNCTION get_pending_consents(p_user_id UUID, p_tenant_id UUID)
RETURNS TABLE (
    consent_type consent_type,
    version VARCHAR(20),
    title VARCHAR(255),
    required BOOLEAN
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        cv.consent_type,
        cv.version,
        cv.title,
        cv.required
    FROM consent_versions cv
    LEFT JOIN user_consents uc ON cv.id = uc.consent_version_id AND uc.user_id = p_user_id
    WHERE cv.tenant_id = p_tenant_id
      AND cv.is_current = TRUE
      AND cv.effective_date <= NOW()
      AND (uc.granted IS NULL OR uc.granted = FALSE);
END;
$$ LANGUAGE plpgsql;

-- ============================================
-- Comments
-- ============================================

COMMENT ON TABLE consent_versions IS 'Versioned consent policies for GDPR/CCPA compliance';
COMMENT ON TABLE user_consents IS 'User consent records with audit trail';
COMMENT ON TABLE data_export_requests IS 'GDPR Article 20 data portability requests';
COMMENT ON TABLE deletion_requests IS 'GDPR Article 17 right to erasure requests';
COMMENT ON TABLE tenant_consent_configs IS 'Tenant-specific consent configuration';
COMMENT ON FUNCTION has_required_consents IS 'Check if user has consented to all required policies';
COMMENT ON FUNCTION get_pending_consents IS 'Get list of pending consents for a user';
