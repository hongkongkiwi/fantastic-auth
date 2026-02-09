-- Risk-Based Authentication Tables
-- Stores risk assessments, user devices, and risk analytics

-- Risk assessments table
CREATE TABLE IF NOT EXISTS risk_assessments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(128) NOT NULL,
    user_id VARCHAR(128),
    score SMALLINT NOT NULL CHECK (score >= 0 AND score <= 100),
    action VARCHAR(32) NOT NULL,
    factors JSONB NOT NULL DEFAULT '[]',
    ip_address INET,
    device_fingerprint VARCHAR(64),
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata JSONB,
    
    CONSTRAINT fk_risk_assessments_tenant 
        FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

-- Indexes for risk assessments
CREATE INDEX idx_risk_assessments_tenant ON risk_assessments(tenant_id);
CREATE INDEX idx_risk_assessments_user ON risk_assessments(tenant_id, user_id);
CREATE INDEX idx_risk_assessments_timestamp ON risk_assessments(timestamp);
CREATE INDEX idx_risk_assessments_score ON risk_assessments(score);
CREATE INDEX idx_risk_assessments_action ON risk_assessments(action);

-- User devices table (for device trust)
CREATE TABLE IF NOT EXISTS user_devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id VARCHAR(128) NOT NULL,
    device_fingerprint VARCHAR(64) NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    trusted BOOLEAN NOT NULL DEFAULT true,
    device_name VARCHAR(255),
    device_type VARCHAR(64),
    user_agent TEXT,
    ip_address INET,
    metadata JSONB,
    
    UNIQUE(user_id, device_fingerprint)
);

-- Indexes for user devices
CREATE INDEX idx_user_devices_user ON user_devices(user_id);
CREATE INDEX idx_user_devices_fingerprint ON user_devices(device_fingerprint);
CREATE INDEX idx_user_devices_last_seen ON user_devices(last_seen);

-- Risk challenges table (for high-risk login challenges)
CREATE TABLE IF NOT EXISTS risk_challenges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(128) NOT NULL,
    user_id VARCHAR(128) NOT NULL,
    challenge_type VARCHAR(32) NOT NULL,
    challenge_token VARCHAR(128) NOT NULL UNIQUE,
    challenge_data JSONB NOT NULL DEFAULT '{}',
    expires_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ,
    completed BOOLEAN NOT NULL DEFAULT false,
    ip_address INET,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    CONSTRAINT fk_risk_challenges_tenant 
        FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

-- Indexes for risk challenges
CREATE INDEX idx_risk_challenges_user ON risk_challenges(tenant_id, user_id);
CREATE INDEX idx_risk_challenges_token ON risk_challenges(challenge_token);
CREATE INDEX idx_risk_challenges_expires ON risk_challenges(expires_at);
CREATE INDEX idx_risk_challenges_completed ON risk_challenges(completed);

-- Risk configuration per tenant
CREATE TABLE IF NOT EXISTS risk_config (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(128) NOT NULL UNIQUE,
    enabled BOOLEAN NOT NULL DEFAULT true,
    weights JSONB NOT NULL DEFAULT '{}',
    thresholds JSONB NOT NULL DEFAULT '{}',
    enabled_factors JSONB NOT NULL DEFAULT '{}',
    velocity_window_seconds INTEGER NOT NULL DEFAULT 300,
    max_velocity_attempts INTEGER NOT NULL DEFAULT 5,
    unusual_hours_start INTEGER NOT NULL DEFAULT 23,
    unusual_hours_end INTEGER NOT NULL DEFAULT 5,
    max_distance_km FLOAT NOT NULL DEFAULT 500.0,
    min_time_between_locations FLOAT NOT NULL DEFAULT 2.0,
    device_trust_days INTEGER NOT NULL DEFAULT 30,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    CONSTRAINT fk_risk_config_tenant 
        FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

-- Indexes for risk config
CREATE INDEX idx_risk_config_tenant ON risk_config(tenant_id);

-- Risk analytics summary (materialized view support table)
CREATE TABLE IF NOT EXISTS risk_analytics (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(128) NOT NULL,
    date DATE NOT NULL,
    total_assessments INTEGER NOT NULL DEFAULT 0,
    avg_score FLOAT,
    blocked_count INTEGER NOT NULL DEFAULT 0,
    challenged_count INTEGER NOT NULL DEFAULT 0,
    step_up_count INTEGER NOT NULL DEFAULT 0,
    allowed_count INTEGER NOT NULL DEFAULT 0,
    
    UNIQUE(tenant_id, date),
    
    CONSTRAINT fk_risk_analytics_tenant 
        FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

-- Indexes for risk analytics
CREATE INDEX idx_risk_analytics_tenant ON risk_analytics(tenant_id);
CREATE INDEX idx_risk_analytics_date ON risk_analytics(date);

-- Enable RLS for risk tables
ALTER TABLE risk_assessments ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE risk_challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE risk_config ENABLE ROW LEVEL SECURITY;
ALTER TABLE risk_analytics ENABLE ROW LEVEL SECURITY;

-- RLS Policies for risk_assessments
CREATE POLICY risk_assessments_tenant_isolation ON risk_assessments
    USING (tenant_id = current_setting('app.current_tenant_id', true));

CREATE POLICY risk_assessments_admin_all ON risk_assessments
    FOR ALL
    TO admin
    USING (true);

-- RLS Policies for user_devices
CREATE POLICY user_devices_tenant_isolation ON user_devices
    USING (EXISTS (
        SELECT 1 FROM users u
        WHERE u.id = user_devices.user_id
        AND u.tenant_id = current_setting('app.current_tenant_id', true)
    ));

CREATE POLICY user_devices_user_select ON user_devices
    FOR SELECT
    USING (user_id = current_setting('app.current_user_id', true));

CREATE POLICY user_devices_admin_all ON user_devices
    FOR ALL
    TO admin
    USING (true);

-- RLS Policies for risk_challenges
CREATE POLICY risk_challenges_tenant_isolation ON risk_challenges
    USING (tenant_id = current_setting('app.current_tenant_id', true));

CREATE POLICY risk_challenges_user_select ON risk_challenges
    FOR SELECT
    USING (user_id = current_setting('app.current_user_id', true));

CREATE POLICY risk_challenges_admin_all ON risk_challenges
    FOR ALL
    TO admin
    USING (true);

-- RLS Policies for risk_config
CREATE POLICY risk_config_tenant_isolation ON risk_config
    USING (tenant_id = current_setting('app.current_tenant_id', true));

CREATE POLICY risk_config_admin_all ON risk_config
    FOR ALL
    TO admin
    USING (true);

-- RLS Policies for risk_analytics
CREATE POLICY risk_analytics_tenant_isolation ON risk_analytics
    USING (tenant_id = current_setting('app.current_tenant_id', true));

CREATE POLICY risk_analytics_admin_all ON risk_analytics
    FOR ALL
    TO admin
    USING (true);

-- Function to update risk_analytics (can be called by a scheduled job)
CREATE OR REPLACE FUNCTION update_risk_analytics(p_tenant_id VARCHAR, p_date DATE)
RETURNS VOID AS $$
BEGIN
    INSERT INTO risk_analytics (
        tenant_id, date, total_assessments, avg_score,
        blocked_count, challenged_count, step_up_count, allowed_count
    )
    SELECT 
        tenant_id,
        p_date,
        COUNT(*),
        AVG(score),
        COUNT(CASE WHEN action = 'block' THEN 1 END),
        COUNT(CASE WHEN action = 'challenge' THEN 1 END),
        COUNT(CASE WHEN action = 'step_up' THEN 1 END),
        COUNT(CASE WHEN action = 'allow' THEN 1 END)
    FROM risk_assessments
    WHERE tenant_id = p_tenant_id
    AND DATE(timestamp) = p_date
    GROUP BY tenant_id
    ON CONFLICT (tenant_id, date) 
    DO UPDATE SET
        total_assessments = EXCLUDED.total_assessments,
        avg_score = EXCLUDED.avg_score,
        blocked_count = EXCLUDED.blocked_count,
        challenged_count = EXCLUDED.challenged_count,
        step_up_count = EXCLUDED.step_up_count,
        allowed_count = EXCLUDED.allowed_count;
END;
$$ LANGUAGE plpgsql;

-- Trigger to auto-insert default risk config for new tenants
CREATE OR REPLACE FUNCTION insert_default_risk_config()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO risk_config (tenant_id)
    VALUES (NEW.id);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS tenant_default_risk_config ON tenants;
CREATE TRIGGER tenant_default_risk_config
    AFTER INSERT ON tenants
    FOR EACH ROW
    EXECUTE FUNCTION insert_default_risk_config();

-- Add comment documenting the risk score thresholds
COMMENT ON TABLE risk_assessments IS 
'Risk assessments for login attempts.
Score thresholds:
- 0-30: Low risk (Allow)
- 31-60: Medium risk (Step-up auth required)
- 61-80: High risk (Challenge required: CAPTCHA + email)
- 81-100: Critical risk (Block)';

-- Add comment on factors JSONB structure
COMMENT ON COLUMN risk_assessments.factors IS 
'JSON array of risk factors with format:
[{"factor": "new_device", "contribution": 30, "description": "...", "details": {...}}, ...]';
