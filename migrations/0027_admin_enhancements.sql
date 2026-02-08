-- Migration: Admin Portal Enhancements
-- Description: Additional tables for enhanced admin features including
-- rate limiting dashboard, API key management, and audit enhancements

-- ============================================
-- Rate Limiting Dashboard Tables
-- ============================================

-- Track rate limit violations for admin dashboard
CREATE TABLE IF NOT EXISTS rate_limit_violations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ip_address INET NOT NULL,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    endpoint VARCHAR(500) NOT NULL,
    limit_type VARCHAR(100) NOT NULL,  -- e.g., 'api', 'auth', 'admin'
    requests_made INTEGER NOT NULL,
    limit_value INTEGER NOT NULL,
    user_agent TEXT,
    country_code CHAR(2),
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Track blocked IPs
CREATE TABLE IF NOT EXISTS blocked_ips (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    ip_address INET NOT NULL,
    blocked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    blocked_until TIMESTAMPTZ,  -- NULL = permanent block
    blocked_by UUID REFERENCES users(id) ON DELETE SET NULL,
    reason TEXT NOT NULL,
    violation_count INTEGER NOT NULL DEFAULT 0,
    auto_blocked BOOLEAN NOT NULL DEFAULT false,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, ip_address)
);

-- Rate limit configuration per tenant (overrides global config)
CREATE TABLE IF NOT EXISTS tenant_rate_limit_configs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    api_per_minute INTEGER NOT NULL DEFAULT 100,
    auth_per_minute INTEGER NOT NULL DEFAULT 10,
    window_seconds INTEGER NOT NULL DEFAULT 60,
    burst_allowance INTEGER NOT NULL DEFAULT 10,
    auto_block_enabled BOOLEAN NOT NULL DEFAULT true,
    auto_block_threshold INTEGER NOT NULL DEFAULT 10,
    auto_block_duration_minutes INTEGER NOT NULL DEFAULT 60,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
    UNIQUE(tenant_id)
);

-- ============================================
-- API Key Management Tables
-- ============================================

-- Extend admin_api_keys table with additional fields for tenant-scoped keys
ALTER TABLE admin_api_keys 
    ADD COLUMN IF NOT EXISTS description TEXT,
    ADD COLUMN IF NOT EXISTS scope JSONB DEFAULT '{"type": "read_only"}',
    ADD COLUMN IF NOT EXISTS allowed_ips JSONB DEFAULT NULL,
    ADD COLUMN IF NOT EXISTS rate_limit_per_minute INTEGER DEFAULT NULL,
    ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS revoked_by UUID REFERENCES users(id) ON DELETE SET NULL;

-- API key usage logs for analytics
CREATE TABLE IF NOT EXISTS api_key_usage_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    api_key_id UUID NOT NULL REFERENCES admin_api_keys(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    endpoint VARCHAR(500) NOT NULL,
    method VARCHAR(10) NOT NULL,
    status_code INTEGER NOT NULL,
    response_time_ms INTEGER,
    ip_address INET,
    user_agent TEXT,
    request_size_bytes INTEGER,
    response_size_bytes INTEGER,
    error_message TEXT,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================
-- Email Template Tables
-- ============================================

-- Tenant-specific email templates
CREATE TABLE IF NOT EXISTS email_templates (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    template_type VARCHAR(100) NOT NULL,
    content JSONB NOT NULL DEFAULT '{}',  -- {subject, html_body, text_body, from_name, from_address}
    is_active BOOLEAN NOT NULL DEFAULT true,
    ab_test_config JSONB DEFAULT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
    UNIQUE(tenant_id, template_type)
);

-- Email template version history
CREATE TABLE IF NOT EXISTS email_template_versions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    template_id UUID NOT NULL REFERENCES email_templates(id) ON DELETE CASCADE,
    version INTEGER NOT NULL,
    content JSONB NOT NULL,
    modified_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    modified_by UUID REFERENCES users(id) ON DELETE SET NULL,
    change_notes TEXT,
    UNIQUE(template_id, version)
);

-- ============================================
-- Custom Domain Tables (extended)
-- ============================================

-- Extend custom_domains with additional fields
ALTER TABLE custom_domains
    ADD COLUMN IF NOT EXISTS verification_token VARCHAR(255),
    ADD COLUMN IF NOT EXISTS verification_method VARCHAR(50) DEFAULT 'dns',
    ADD COLUMN IF NOT EXISTS last_verification_check TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS last_verification_error TEXT,
    ADD COLUMN IF NOT EXISTS ssl_issuer VARCHAR(255),
    ADD COLUMN IF NOT EXISTS ssl_issued_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS ssl_expires_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS ssl_auto_renew BOOLEAN DEFAULT true,
    ADD COLUMN IF NOT EXISTS ssl_certificate_pem TEXT,
    ADD COLUMN IF NOT EXISTS ssl_private_key_encrypted TEXT,
    ADD COLUMN IF NOT EXISTS cdn_enabled BOOLEAN DEFAULT false,
    ADD COLUMN IF NOT EXISTS cdn_config JSONB DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS settings JSONB DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS health_status VARCHAR(50) DEFAULT 'unknown',
    ADD COLUMN IF NOT EXISTS health_last_checked TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS metadata JSONB DEFAULT '{}';

-- Domain health check history
CREATE TABLE IF NOT EXISTS domain_health_checks (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    domain_id UUID NOT NULL REFERENCES custom_domains(id) ON DELETE CASCADE,
    checked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    overall_status VARCHAR(50) NOT NULL,
    dns_status VARCHAR(50),
    ssl_status VARCHAR(50),
    http_status VARCHAR(50),
    response_time_ms INTEGER,
    error_message TEXT,
    details JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================
-- Enhanced Audit Tables
-- ============================================

-- Advanced audit log filtering and insights
CREATE TABLE IF NOT EXISTS audit_insights (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    insight_type VARCHAR(100) NOT NULL,  -- e.g., 'anomaly', 'pattern', 'recommendation'
    severity VARCHAR(20) NOT NULL,  -- 'info', 'warning', 'critical'
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    related_events JSONB DEFAULT '[]',  -- Array of audit log IDs
    metadata JSONB DEFAULT '{}',
    acknowledged_at TIMESTAMPTZ,
    acknowledged_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Audit log exports tracking
CREATE TABLE IF NOT EXISTS audit_exports (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    status VARCHAR(50) NOT NULL DEFAULT 'pending',  -- pending, processing, completed, failed
    format VARCHAR(20) NOT NULL,  -- csv, json, parquet
    date_range_start TIMESTAMPTZ NOT NULL,
    date_range_end TIMESTAMPTZ NOT NULL,
    filters JSONB DEFAULT '{}',  -- Applied filters
    file_path TEXT,
    file_size_bytes INTEGER,
    record_count INTEGER,
    error_message TEXT,
    requested_by UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ  -- When the export file should be deleted
);

-- ============================================
-- Indexes for Performance
-- ============================================

-- Rate limit violations indexes
CREATE INDEX IF NOT EXISTS idx_rate_limit_violations_tenant_timestamp 
    ON rate_limit_violations(tenant_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_rate_limit_violations_ip 
    ON rate_limit_violations(tenant_id, ip_address);
CREATE INDEX IF NOT EXISTS idx_rate_limit_violations_endpoint 
    ON rate_limit_violations(tenant_id, endpoint);

-- Blocked IPs indexes
CREATE INDEX IF NOT EXISTS idx_blocked_ips_tenant 
    ON blocked_ips(tenant_id, blocked_at DESC);
CREATE INDEX IF NOT EXISTS idx_blocked_ips_active 
    ON blocked_ips(tenant_id, ip_address) 
    WHERE blocked_until IS NULL OR blocked_until > NOW();

-- API key usage logs indexes
CREATE INDEX IF NOT EXISTS idx_api_key_usage_logs_key 
    ON api_key_usage_logs(api_key_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_api_key_usage_logs_tenant 
    ON api_key_usage_logs(tenant_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_api_key_usage_logs_endpoint 
    ON api_key_usage_logs(tenant_id, endpoint);

-- Domain health checks indexes
CREATE INDEX IF NOT EXISTS idx_domain_health_checks_domain 
    ON domain_health_checks(domain_id, checked_at DESC);

-- Email templates indexes
CREATE INDEX IF NOT EXISTS idx_email_templates_tenant 
    ON email_templates(tenant_id, template_type);

-- Audit insights indexes
CREATE INDEX IF NOT EXISTS idx_audit_insights_tenant 
    ON audit_insights(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_insights_unacknowledged 
    ON audit_insights(tenant_id, insight_type) 
    WHERE acknowledged_at IS NULL;

-- ============================================
-- RLS Policies
-- ============================================

-- Enable RLS on new tables
ALTER TABLE rate_limit_violations ENABLE ROW LEVEL SECURITY;
ALTER TABLE blocked_ips ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_rate_limit_configs ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_key_usage_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE email_templates ENABLE ROW LEVEL SECURITY;
ALTER TABLE email_template_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE domain_health_checks ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_insights ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_exports ENABLE ROW LEVEL SECURITY;

ALTER TABLE rate_limit_violations FORCE ROW LEVEL SECURITY;
ALTER TABLE blocked_ips FORCE ROW LEVEL SECURITY;
ALTER TABLE tenant_rate_limit_configs FORCE ROW LEVEL SECURITY;
ALTER TABLE api_key_usage_logs FORCE ROW LEVEL SECURITY;
ALTER TABLE email_templates FORCE ROW LEVEL SECURITY;
ALTER TABLE email_template_versions FORCE ROW LEVEL SECURITY;
ALTER TABLE domain_health_checks FORCE ROW LEVEL SECURITY;
ALTER TABLE audit_insights FORCE ROW LEVEL SECURITY;
ALTER TABLE audit_exports FORCE ROW LEVEL SECURITY;

-- Rate limit violations: tenant isolation
CREATE POLICY tenant_isolation_rate_limit_violations ON rate_limit_violations
    FOR ALL TO vault_app
    USING (tenant_id = current_tenant_id() AND is_admin())
    WITH CHECK (tenant_id = current_tenant_id() AND is_admin());

-- Blocked IPs: tenant isolation
CREATE POLICY tenant_isolation_blocked_ips ON blocked_ips
    FOR ALL TO vault_app
    USING (tenant_id = current_tenant_id() AND is_admin())
    WITH CHECK (tenant_id = current_tenant_id() AND is_admin());

-- Tenant rate limit configs: tenant isolation
CREATE POLICY tenant_isolation_tenant_rate_limit_configs ON tenant_rate_limit_configs
    FOR ALL TO vault_app
    USING (tenant_id = current_tenant_id() AND is_admin())
    WITH CHECK (tenant_id = current_tenant_id() AND is_admin());

-- API key usage logs: tenant isolation
CREATE POLICY tenant_isolation_api_key_usage_logs ON api_key_usage_logs
    FOR ALL TO vault_app
    USING (tenant_id = current_tenant_id() AND is_admin())
    WITH CHECK (tenant_id = current_tenant_id() AND is_admin());

-- Email templates: tenant isolation
CREATE POLICY tenant_isolation_email_templates ON email_templates
    FOR ALL TO vault_app
    USING (tenant_id = current_tenant_id() AND is_admin())
    WITH CHECK (tenant_id = current_tenant_id() AND is_admin());

-- Email template versions: tenant isolation via template
CREATE POLICY tenant_isolation_email_template_versions ON email_template_versions
    FOR ALL TO vault_app
    USING (
        template_id IN (
            SELECT id FROM email_templates
            WHERE tenant_id = current_tenant_id() AND is_admin()
        )
    )
    WITH CHECK (
        template_id IN (
            SELECT id FROM email_templates
            WHERE tenant_id = current_tenant_id() AND is_admin()
        )
    );

-- Domain health checks: tenant isolation via domain
CREATE POLICY tenant_isolation_domain_health_checks ON domain_health_checks
    FOR ALL TO vault_app
    USING (
        domain_id IN (
            SELECT id FROM custom_domains
            WHERE tenant_id = current_tenant_id() AND is_admin()
        )
    )
    WITH CHECK (
        domain_id IN (
            SELECT id FROM custom_domains
            WHERE tenant_id = current_tenant_id() AND is_admin()
        )
    );

-- Audit insights: tenant isolation
CREATE POLICY tenant_isolation_audit_insights ON audit_insights
    FOR ALL TO vault_app
    USING (tenant_id = current_tenant_id() AND is_admin())
    WITH CHECK (tenant_id = current_tenant_id() AND is_admin());

-- Audit exports: tenant isolation
CREATE POLICY tenant_isolation_audit_exports ON audit_exports
    FOR ALL TO vault_app
    USING (tenant_id = current_tenant_id() AND is_admin())
    WITH CHECK (tenant_id = current_tenant_id() AND is_admin());

-- ============================================
-- Comments
-- ============================================

COMMENT ON TABLE rate_limit_violations IS 'Tracks rate limit violations for admin dashboard and security monitoring';
COMMENT ON TABLE blocked_ips IS 'IP addresses blocked due to rate limit violations or security concerns';
COMMENT ON TABLE api_key_usage_logs IS 'Analytics logs for API key usage';
COMMENT ON TABLE email_templates IS 'Tenant-specific email template overrides';
COMMENT ON TABLE domain_health_checks IS 'Health check history for custom domains';
COMMENT ON TABLE audit_insights IS 'AI-generated insights and anomaly detection from audit logs';
COMMENT ON TABLE audit_exports IS 'Audit log export jobs tracking';
