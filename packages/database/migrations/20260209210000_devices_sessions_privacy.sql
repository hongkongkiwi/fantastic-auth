-- Migration: Device Management, Enhanced Sessions, and Privacy/GDPR Tables
-- Created: 2026-02-09

-- ============================================
-- 1. Device Management Tables
-- ============================================

CREATE TABLE user_devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    
    -- Device fingerprinting
    fingerprint_hash VARCHAR(255) NOT NULL,
    device_id VARCHAR(255), -- Client-provided device identifier
    
    -- Trust & Security
    trust_score INT NOT NULL DEFAULT 50 CHECK (trust_score >= 0 AND trust_score <= 100),
    is_trusted BOOLEAN NOT NULL DEFAULT false,
    is_blocked BOOLEAN NOT NULL DEFAULT false,
    
    -- Device Info
    device_name VARCHAR(255),
    device_type VARCHAR(50) CHECK (device_type IN ('desktop', 'mobile', 'tablet', 'unknown')),
    device_model VARCHAR(255),
    
    -- OS & Browser
    os VARCHAR(100),
    os_version VARCHAR(100),
    browser VARCHAR(100),
    browser_version VARCHAR(100),
    
    -- Security Posture
    encryption_status VARCHAR(50) CHECK (encryption_status IN ('enabled', 'disabled', 'unknown')),
    has_password BOOLEAN DEFAULT false,
    has_biometric BOOLEAN DEFAULT false,
    screen_lock_enabled BOOLEAN DEFAULT false,
    
    -- Location
    ip_address INET,
    country_code VARCHAR(2),
    city VARCHAR(255),
    location_approximate VARCHAR(255),
    
    -- Metadata
    user_agent TEXT,
    last_seen_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    first_seen_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    
    -- Unique constraint per user per fingerprint
    CONSTRAINT unique_user_device UNIQUE (user_id, fingerprint_hash)
);

CREATE INDEX idx_user_devices_user_id ON user_devices(user_id);
CREATE INDEX idx_user_devices_tenant_id ON user_devices(tenant_id);
CREATE INDEX idx_user_devices_fingerprint ON user_devices(fingerprint_hash);
CREATE INDEX idx_user_devices_is_trusted ON user_devices(user_id, is_trusted);
CREATE INDEX idx_user_devices_last_seen ON user_devices(last_seen_at);

-- Device trust policies per tenant
CREATE TABLE device_trust_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL UNIQUE REFERENCES tenants(id) ON DELETE CASCADE,
    
    -- Policy Settings
    require_trusted_device BOOLEAN NOT NULL DEFAULT false,
    require_encryption BOOLEAN NOT NULL DEFAULT true,
    require_password_protection BOOLEAN NOT NULL DEFAULT true,
    require_biometric BOOLEAN NOT NULL DEFAULT false,
    
    -- Auto-revocation
    max_device_age_days INT NOT NULL DEFAULT 90 CHECK (max_device_age_days > 0),
    auto_revoke_inactive_days INT NOT NULL DEFAULT 30 CHECK (auto_revoke_inactive_days > 0),
    
    -- Allowed device types
    allowed_device_types TEXT[] NOT NULL DEFAULT ARRAY['desktop', 'mobile', 'tablet'],
    
    -- Score thresholds
    min_trust_score_for_auto_approve INT NOT NULL DEFAULT 70 CHECK (min_trust_score_for_auto_approve >= 0 AND min_trust_score_for_auto_approve <= 100),
    
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Device verification tokens (for email/SMS verification)
CREATE TABLE device_verifications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id UUID NOT NULL REFERENCES user_devices(id) ON DELETE CASCADE,
    verification_token VARCHAR(255) NOT NULL,
    verification_method VARCHAR(50) NOT NULL CHECK (verification_method IN ('email', 'sms', 'totp', 'push')),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    verified_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_device_verifications_device ON device_verifications(device_id);
CREATE INDEX idx_device_verifications_token ON device_verifications(verification_token);

-- ============================================
-- 2. Enhanced Session Tracking
-- ============================================

-- Add columns to existing sessions table
ALTER TABLE sessions 
    ADD COLUMN IF NOT EXISTS device_id UUID REFERENCES user_devices(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS risk_score INT DEFAULT 0 CHECK (risk_score >= 0 AND risk_score <= 100),
    ADD COLUMN IF NOT EXISTS risk_factors TEXT[], -- ['new_device', 'new_location', 'impossible_travel']
    ADD COLUMN IF NOT EXISTS is_suspicious BOOLEAN DEFAULT false,
    ADD COLUMN IF NOT EXISTS is_current BOOLEAN DEFAULT false,
    ADD COLUMN IF NOT EXISTS factors TEXT[], -- ['password', 'mfa_totp', 'webauthn', 'biometric']
    ADD COLUMN IF NOT EXISTS mfa_verified BOOLEAN DEFAULT false,
    ADD COLUMN IF NOT EXISTS mfa_methods TEXT[], -- ['totp', 'sms', 'email']
    ADD COLUMN IF NOT EXISTS country_code VARCHAR(2),
    ADD COLUMN IF NOT EXISTS city VARCHAR(255),
    ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMP WITH TIME ZONE,
    ADD COLUMN IF NOT EXISTS revoked_reason VARCHAR(255);

CREATE INDEX IF NOT EXISTS idx_sessions_device_id ON sessions(device_id);
CREATE INDEX IF NOT EXISTS idx_sessions_risk_score ON sessions(risk_score);
CREATE INDEX IF NOT EXISTS idx_sessions_is_suspicious ON sessions(is_suspicious);

-- Session activity log (for audit trail)
CREATE TABLE session_activities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    
    activity_type VARCHAR(100) NOT NULL, -- 'login', 'mfa_verified', 'step_up', 'refresh', 'revoked'
    activity_data JSONB, -- Additional context
    
    -- Location & Device at time of activity
    ip_address INET,
    country_code VARCHAR(2),
    city VARCHAR(255),
    device_id UUID REFERENCES user_devices(id),
    
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_session_activities_session ON session_activities(session_id);
CREATE INDEX idx_session_activities_user ON session_activities(user_id);
CREATE INDEX idx_session_activities_created ON session_activities(created_at);

-- ============================================
-- 3. Privacy & GDPR Tables
-- ============================================

-- Data export requests (GDPR Article 20)
CREATE TABLE data_exports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    
    -- Export metadata
    status VARCHAR(50) NOT NULL DEFAULT 'pending' 
        CHECK (status IN ('pending', 'processing', 'ready', 'expired', 'failed')),
    format VARCHAR(50) NOT NULL DEFAULT 'json' CHECK (format IN ('json', 'csv')),
    
    -- File info
    file_path VARCHAR(500),
    file_size_bytes BIGINT,
    file_checksum VARCHAR(255),
    
    -- Data categories included
    data_categories TEXT[] NOT NULL DEFAULT ARRAY['profile', 'activity', 'consents'],
    
    -- Timestamps
    expires_at TIMESTAMP WITH TIME ZONE,
    downloaded_at TIMESTAMP WITH TIME ZONE,
    download_count INT DEFAULT 0,
    
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_data_exports_user ON data_exports(user_id);
CREATE INDEX idx_data_exports_status ON data_exports(status);
CREATE INDEX idx_data_exports_created ON data_exports(created_at);

-- Account deletion requests (GDPR Article 17)
CREATE TABLE account_deletion_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    
    status VARCHAR(50) NOT NULL DEFAULT 'pending' 
        CHECK (status IN ('pending', 'approved', 'processing', 'completed', 'cancelled', 'rejected')),
    
    -- Request details
    request_reason TEXT,
    confirmation_token VARCHAR(255),
    confirmed_at TIMESTAMP WITH TIME ZONE,
    
    -- Approval workflow
    approved_by UUID REFERENCES users(id),
    approved_at TIMESTAMP WITH TIME ZONE,
    rejection_reason TEXT,
    
    -- Deletion tracking
    scheduled_for TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_deletion_requests_user ON account_deletion_requests(user_id);
CREATE INDEX idx_deletion_requests_status ON account_deletion_requests(status);

-- Consent management
CREATE TABLE consent_records (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    
    consent_type VARCHAR(100) NOT NULL, -- 'analytics', 'marketing', 'third_party'
    consent_version VARCHAR(50) NOT NULL, -- Version of consent terms
    
    granted BOOLEAN NOT NULL,
    granted_at TIMESTAMP WITH TIME ZONE,
    
    -- Context
    ip_address INET,
    user_agent TEXT,
    
    -- Withdrawal
    withdrawn_at TIMESTAMP WITH TIME ZONE,
    withdrawal_reason TEXT,
    
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    
    CONSTRAINT unique_user_consent UNIQUE (user_id, consent_type, consent_version)
);

CREATE INDEX idx_consent_records_user ON consent_records(user_id);
CREATE INDEX idx_consent_records_type ON consent_records(consent_type);
CREATE INDEX idx_consent_records_granted ON consent_records(user_id, consent_type, granted);

-- Data processing records (GDPR Article 30)
CREATE TABLE data_processing_records (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    
    -- Processing details
    purpose VARCHAR(255) NOT NULL,
    data_categories TEXT[] NOT NULL,
    data_subjects TEXT[] NOT NULL, -- ['users', 'employees', 'customers']
    
    -- Legal basis
    legal_basis VARCHAR(50) NOT NULL CHECK (legal_basis IN ('consent', 'contract', 'legal_obligation', 'vital_interests', 'public_task', 'legitimate_interest')),
    legal_basis_description TEXT,
    
    -- Retention
    retention_period VARCHAR(255) NOT NULL, -- "1 year", "7 years"
    retention_justification TEXT,
    
    -- Recipients
    internal_recipients TEXT[],
    external_recipients TEXT[], -- Third parties
    
    -- Security measures
    security_measures TEXT[],
    
    -- DPIA (Data Protection Impact Assessment)
    dpia_required BOOLEAN DEFAULT false,
    dpia_completed_at TIMESTAMP WITH TIME ZONE,
    
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- ============================================
-- 4. Security Dashboard Tables
-- ============================================

-- Security alerts
CREATE TABLE security_alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE, -- Nullable for tenant-wide alerts
    
    -- Alert details
    severity VARCHAR(50) NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    category VARCHAR(50) NOT NULL CHECK (category IN ('login', 'device', 'session', 'anomaly', 'policy', 'mfa', 'api')),
    
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    
    -- Related entities
    related_session_id UUID REFERENCES sessions(id),
    related_device_id UUID REFERENCES user_devices(id),
    
    -- Alert data
    alert_data JSONB,
    
    -- Resolution
    status VARCHAR(50) NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'acknowledged', 'resolved', 'false_positive')),
    acknowledged_by UUID REFERENCES users(id),
    acknowledged_at TIMESTAMP WITH TIME ZONE,
    resolved_by UUID REFERENCES users(id),
    resolved_at TIMESTAMP WITH TIME ZONE,
    resolution_notes TEXT,
    
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_security_alerts_tenant ON security_alerts(tenant_id);
CREATE INDEX idx_security_alerts_user ON security_alerts(user_id);
CREATE INDEX idx_security_alerts_severity ON security_alerts(severity);
CREATE INDEX idx_security_alerts_status ON security_alerts(status);
CREATE INDEX idx_security_alerts_created ON security_alerts(created_at);

-- Security recommendations
CREATE TABLE security_recommendations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    
    priority VARCHAR(50) NOT NULL CHECK (priority IN ('critical', 'high', 'medium', 'low')),
    category VARCHAR(100) NOT NULL,
    
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    
    -- Action
    action_text VARCHAR(255) NOT NULL,
    action_route VARCHAR(255), -- Frontend route to navigate to
    action_api_endpoint VARCHAR(255), -- API endpoint to call
    
    -- Status
    is_completed BOOLEAN NOT NULL DEFAULT false,
    completed_by UUID REFERENCES users(id),
    completed_at TIMESTAMP WITH TIME ZONE,
    
    -- Auto-expiry
    expires_at TIMESTAMP WITH TIME ZONE,
    
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_security_recommendations_tenant ON security_recommendations(tenant_id);
CREATE INDEX idx_security_recommendations_priority ON security_recommendations(priority);
CREATE INDEX idx_security_recommendations_completed ON security_recommendations(is_completed);

-- Security scores history
CREATE TABLE security_scores (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    
    overall_score INT NOT NULL CHECK (overall_score >= 0 AND overall_score <= 100),
    
    -- Component scores
    mfa_score INT CHECK (mfa_score >= 0 AND mfa_score <= 100),
    password_score INT CHECK (password_score >= 0 AND password_score <= 100),
    session_score INT CHECK (session_score >= 0 AND session_score <= 100),
    device_score INT CHECK (device_score >= 0 AND device_score <= 100),
    policy_score INT CHECK (policy_score >= 0 AND policy_score <= 100),
    
    calculated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_security_scores_tenant ON security_scores(tenant_id);
CREATE INDEX idx_security_scores_calculated ON security_scores(calculated_at);

-- ============================================
-- 5. Triggers for updated_at
-- ============================================

CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply trigger to all tables with updated_at
CREATE TRIGGER update_user_devices_updated_at BEFORE UPDATE ON user_devices
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_device_trust_policies_updated_at BEFORE UPDATE ON device_trust_policies
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_data_exports_updated_at BEFORE UPDATE ON data_exports
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_account_deletion_requests_updated_at BEFORE UPDATE ON account_deletion_requests
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_consent_records_updated_at BEFORE UPDATE ON consent_records
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_data_processing_records_updated_at BEFORE UPDATE ON data_processing_records
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_security_alerts_updated_at BEFORE UPDATE ON security_alerts
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_security_recommendations_updated_at BEFORE UPDATE ON security_recommendations
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
