-- Geographic Restrictions Migration
-- Adds support for country-based access control and VPN/proxy detection

-- Tenant geo restriction settings
CREATE TABLE IF NOT EXISTS tenant_geo_settings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    enabled BOOLEAN NOT NULL DEFAULT false,
    policy VARCHAR(20) NOT NULL DEFAULT 'block_list', -- 'allow_list' or 'block_list'
    country_list JSONB NOT NULL DEFAULT '[]', -- Array of ISO 3166-1 alpha-2 country codes
    allow_vpn BOOLEAN NOT NULL DEFAULT true,
    block_anonymous_proxies BOOLEAN NOT NULL DEFAULT false,
    block_hosting_providers BOOLEAN NOT NULL DEFAULT false,
    custom_vpn_asns JSONB NOT NULL DEFAULT '[]', -- Array of ASN numbers
    custom_hosting_asns JSONB NOT NULL DEFAULT '[]', -- Array of ASN numbers
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
    UNIQUE(tenant_id)
);

-- Index for tenant lookups
CREATE INDEX idx_tenant_geo_settings_tenant_id ON tenant_geo_settings(tenant_id);

-- Geo audit log for blocked access attempts
CREATE TABLE IF NOT EXISTS geo_audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    session_id UUID REFERENCES sessions(id) ON DELETE SET NULL,
    action VARCHAR(50) NOT NULL, -- 'geo.access_denied', 'geo.vpn_blocked', etc.
    ip_address INET,
    country_code VARCHAR(2),
    is_vpn BOOLEAN NOT NULL DEFAULT false,
    is_anonymous_proxy BOOLEAN NOT NULL DEFAULT false,
    is_hosting_provider BOOLEAN NOT NULL DEFAULT false,
    reason TEXT,
    user_agent TEXT,
    success BOOLEAN NOT NULL DEFAULT false,
    metadata JSONB,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for geo audit log queries
CREATE INDEX idx_geo_audit_tenant_id ON geo_audit_log(tenant_id);
CREATE INDEX idx_geo_audit_timestamp ON geo_audit_log(timestamp);
CREATE INDEX idx_geo_audit_action ON geo_audit_log(action);
CREATE INDEX idx_geo_audit_country ON geo_audit_log(country_code);
CREATE INDEX idx_geo_audit_ip ON geo_audit_log(ip_address);

-- User geo anomaly tracking (for alerting on logins from new countries)
CREATE TABLE IF NOT EXISTS user_geo_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    country_code VARCHAR(2) NOT NULL,
    ip_range INET, -- CIDR notation for the IP range
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    login_count INTEGER NOT NULL DEFAULT 1,
    is_trusted BOOLEAN NOT NULL DEFAULT false, -- User has confirmed this location
    UNIQUE(user_id, country_code)
);

-- Indexes for geo history
CREATE INDEX idx_user_geo_history_user_id ON user_geo_history(user_id);
CREATE INDEX idx_user_geo_history_tenant_id ON user_geo_history(tenant_id);
CREATE INDEX idx_user_geo_history_country ON user_geo_history(country_code);

-- RLS policies for geo restriction tables
ALTER TABLE tenant_geo_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE geo_audit_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_geo_history ENABLE ROW LEVEL SECURITY;

-- Tenant geo settings policies
CREATE POLICY tenant_geo_settings_isolation ON tenant_geo_settings
    USING (tenant_id = current_setting('app.current_tenant_id', true)::UUID);

-- Geo audit log policies
CREATE POLICY geo_audit_log_isolation ON geo_audit_log
    USING (tenant_id = current_setting('app.current_tenant_id', true)::UUID);

-- User geo history policies
CREATE POLICY user_geo_history_isolation ON user_geo_history
    USING (tenant_id = current_setting('app.current_tenant_id', true)::UUID);

-- Function to update user_geo_history on login
CREATE OR REPLACE FUNCTION update_user_geo_history(
    p_user_id UUID,
    p_tenant_id UUID,
    p_country_code VARCHAR(2),
    p_ip_address INET
) RETURNS TABLE (
    is_new_country BOOLEAN,
    is_suspicious BOOLEAN
) AS $$
DECLARE
    v_is_new BOOLEAN;
    v_is_suspicious BOOLEAN;
BEGIN
    -- Check if this is a new country for the user
    SELECT NOT EXISTS (
        SELECT 1 FROM user_geo_history 
        WHERE user_id = p_user_id AND country_code = p_country_code
    ) INTO v_is_new;
    
    -- Consider suspicious if new country and not trusted
    SELECT v_is_new AND NOT is_trusted INTO v_is_suspicious
    FROM user_geo_history 
    WHERE user_id = p_user_id AND country_code = p_country_code;
    
    -- Insert or update the geo history
    INSERT INTO user_geo_history (
        user_id, tenant_id, country_code, ip_range, login_count, is_trusted
    ) VALUES (
        p_user_id, p_tenant_id, p_country_code, 
        network(p_ip_address), 1, false
    )
    ON CONFLICT (user_id, country_code) DO UPDATE SET
        last_seen = NOW(),
        login_count = user_geo_history.login_count + 1,
        ip_range = EXCLUDED.ip_range;
    
    RETURN QUERY SELECT v_is_new, COALESCE(v_is_suspicious, v_is_new);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function to log geo restriction events
CREATE OR REPLACE FUNCTION log_geo_audit_event(
    p_tenant_id UUID,
    p_user_id UUID,
    p_session_id UUID,
    p_action VARCHAR(50),
    p_ip_address INET,
    p_country_code VARCHAR(2),
    p_is_vpn BOOLEAN,
    p_is_anonymous_proxy BOOLEAN,
    p_is_hosting_provider BOOLEAN,
    p_reason TEXT,
    p_user_agent TEXT,
    p_success BOOLEAN,
    p_metadata JSONB
) RETURNS UUID AS $$
DECLARE
    v_id UUID;
BEGIN
    INSERT INTO geo_audit_log (
        tenant_id, user_id, session_id, action, ip_address, country_code,
        is_vpn, is_anonymous_proxy, is_hosting_provider, reason, user_agent,
        success, metadata
    ) VALUES (
        p_tenant_id, p_user_id, p_session_id, p_action, p_ip_address, p_country_code,
        p_is_vpn, p_is_anonymous_proxy, p_is_hosting_provider, p_reason, p_user_agent,
        p_success, p_metadata
    )
    RETURNING id INTO v_id;
    
    RETURN v_id;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- View for geo restriction analytics
CREATE OR REPLACE VIEW geo_analytics_summary AS
SELECT 
    tenant_id,
    DATE_TRUNC('day', timestamp) AS date,
    country_code,
    action,
    COUNT(*) AS event_count,
    COUNT(DISTINCT ip_address) AS unique_ips,
    COUNT(DISTINCT user_id) AS unique_users
FROM geo_audit_log
GROUP BY tenant_id, DATE_TRUNC('day', timestamp), country_code, action;

-- Comments
COMMENT ON TABLE tenant_geo_settings IS 'Geographic restriction settings per tenant';
COMMENT ON TABLE geo_audit_log IS 'Audit log for geo-restricted access attempts';
COMMENT ON TABLE user_geo_history IS 'Track user login locations for anomaly detection';
COMMENT ON FUNCTION update_user_geo_history IS 'Update user geo history and return if location is new/suspicious';
COMMENT ON FUNCTION log_geo_audit_event IS 'Log a geo restriction audit event';
