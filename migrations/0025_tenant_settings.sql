-- Comprehensive Tenant Settings Migration
-- Creates tables for per-tenant customization of all auth and security settings

-- ============================================
-- Main Tenant Settings Table
-- ============================================
CREATE TABLE tenant_settings (
    tenant_id UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    
    -- 1. Authentication Settings
    auth_settings JSONB NOT NULL DEFAULT '{
        "allow_registration": true,
        "require_email_verification": true,
        "allowed_auth_methods": ["password", "magic_link", "otp_email"],
        "default_auth_method": "password",
        "allow_anonymous_auth": false,
        "allow_passwordless": true,
        "require_strong_auth": false,
        "step_up_auth_rules": []
    }',
    
    -- 2. Security Settings
    security_settings JSONB NOT NULL DEFAULT '{
        "password_policy": {
            "min_length": 12,
            "max_length": 128,
            "require_uppercase": true,
            "require_lowercase": true,
            "require_numbers": true,
            "require_special": true,
            "special_chars": "!@#$%^&*()_+-=[]{}|;:,.<>?",
            "max_consecutive_chars": 3,
            "prevent_common_passwords": true,
            "history_count": 5,
            "check_breach": true,
            "enforcement_mode": "block",
            "min_entropy": 50.0,
            "prevent_user_info": true
        },
        "session_lifetime": {
            "access_token_minutes": 15,
            "refresh_token_days": 7,
            "absolute_timeout_hours": 24,
            "idle_timeout_minutes": 30
        },
        "session_limits": {
            "max_concurrent_sessions": 5,
            "eviction_policy": "oldest_first",
            "enforce_for_ip": false,
            "max_sessions_per_ip": 3
        },
        "mfa_settings": {
            "require_mfa": false,
            "allowed_methods": ["totp", "email", "sms", "webauthn"],
            "grace_period_days": 7,
            "require_mfa_for_roles": []
        },
        "lockout_policy": {
            "max_failed_attempts": 5,
            "lockout_duration_minutes": 30,
            "reset_after_minutes": 60
        }
    }',
    
    -- 3. Organization Settings
    org_settings JSONB NOT NULL DEFAULT '{
        "organizations_enabled": false,
        "membership_required": false,
        "max_organizations_per_user": 100,
        "default_org_role": "member",
        "creator_role": "admin",
        "allow_user_created_orgs": true,
        "auto_create_first_org": false,
        "verified_domains_enabled": false,
        "default_membership_limit": 5,
        "allow_personal_accounts": true,
        "org_creation_approval_required": false
    }',
    
    -- 4. Branding Settings
    branding_settings JSONB NOT NULL DEFAULT '{
        "brand_name": "Vault",
        "brand_logo_url": null,
        "brand_favicon_url": null,
        "primary_color": "#0066FF",
        "accent_color": "#00D4AA",
        "dark_mode_enabled": true,
        "custom_css": null,
        "login_page_layout": "centered",
        "custom_domain": null,
        "terms_of_service_url": null,
        "privacy_policy_url": null,
        "support_url": null,
        "show_powered_by": true
    }',
    
    -- 5. Email Settings
    email_settings JSONB NOT NULL DEFAULT '{
        "from_address": "noreply@example.com",
        "from_name": "Vault",
        "reply_to": null,
        "welcome_email_enabled": true,
        "verification_email_enabled": true,
        "password_reset_enabled": true,
        "mfa_email_enabled": true,
        "org_invite_email_enabled": true,
        "security_alert_emails": true,
        "email_templates": {},
        "custom_smtp": null
    }',
    
    -- 6. OAuth & SSO Settings
    oauth_settings JSONB NOT NULL DEFAULT '{
        "oauth_providers": [],
        "sso_enabled": false,
        "sso_settings": {},
        "auto_redirect_sso": false,
        "allow_social_logins": true,
        "account_linking": "automatic",
        "require_verified_email_for_linking": true
    }',
    
    -- 7. Localization Settings
    localization_settings JSONB NOT NULL DEFAULT '{
        "default_language": "en",
        "supported_languages": ["en"],
        "timezone": "UTC",
        "date_format": "ISO",
        "time_format": "24h",
        "gdpr_compliance_mode": false,
        "data_residency_region": null
    }',
    
    -- 8. Webhook Settings
    webhook_settings JSONB NOT NULL DEFAULT '{
        "webhooks_enabled": true,
        "webhook_endpoints": [],
        "webhook_events": ["user.created", "user.updated", "user.deleted", "session.created", "session.revoked"],
        "webhook_retries": {
            "max_attempts": 5,
            "retry_schedule": [60, 300, 900, 3600],
            "timeout_seconds": 30
        },
        "signing_secret_rotation_days": 90
    }',
    
    -- 9. Privacy & Compliance Settings
    privacy_settings JSONB NOT NULL DEFAULT '{
        "analytics_enabled": true,
        "session_recording": false,
        "consent_required": true,
        "consent_types": ["tos", "privacy"],
        "data_retention_days": 90,
        "anonymize_ip": false,
        "allow_data_export": true,
        "allow_account_deletion": true,
        "deletion_grace_period_days": 30,
        "cookie_consent_required": true,
        "min_age_requirement": 13
    }',
    
    -- 10. Advanced/Developer Settings
    advanced_settings JSONB NOT NULL DEFAULT '{
        "jwt_claims": {},
        "token_format": "jwt",
        "refresh_token_rotation": "always",
        "cookie_same_site": "lax",
        "cookie_domain": null,
        "cookie_secure": true,
        "allowed_callback_urls": ["*"],
        "allowed_logout_urls": ["*"],
        "custom_metadata_schema": {},
        "feature_flags": {},
        "api_version": "v1",
        "strict_mode": false
    }',
    
    -- Metadata
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by UUID REFERENCES users(id)
);

-- Create index for efficient lookups
CREATE INDEX idx_tenant_settings_tenant ON tenant_settings(tenant_id);

-- ============================================
-- Tenant Setting Change History (Audit)
-- ============================================
CREATE TABLE tenant_settings_history (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    changed_by UUID REFERENCES users(id),
    change_type VARCHAR(50) NOT NULL, -- 'auth', 'security', 'org', 'branding', etc.
    previous_value JSONB NOT NULL,
    new_value JSONB NOT NULL,
    reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_settings_history_tenant ON tenant_settings_history(tenant_id, created_at DESC);
CREATE INDEX idx_settings_history_change_type ON tenant_settings_history(change_type);

-- ============================================
-- Per-Tenant OAuth Provider Configurations
-- ============================================
CREATE TABLE tenant_oauth_providers (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    provider_id VARCHAR(100) NOT NULL, -- 'google', 'github', 'custom_oidc', etc.
    display_name VARCHAR(255) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    
    -- Provider configuration (encrypted sensitive fields)
    client_id VARCHAR(500) NOT NULL,
    client_secret_encrypted TEXT NOT NULL, -- Encrypted with tenant key
    redirect_uri VARCHAR(500),
    
    -- OIDC/SAML specific
    authorization_endpoint VARCHAR(500),
    token_endpoint VARCHAR(500),
    userinfo_endpoint VARCHAR(500),
    oidc_discovery_endpoint VARCHAR(500),
    scopes TEXT[], -- Array of scopes
    
    -- Custom provider settings
    custom_config JSONB DEFAULT '{}',
    
    -- Attribute mapping for SSO
    attribute_mapping JSONB DEFAULT '{
        "email": "email",
        "name": "name",
        "picture": "picture"
    }',
    
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    UNIQUE(tenant_id, provider_id)
);

CREATE INDEX idx_oauth_providers_tenant ON tenant_oauth_providers(tenant_id);
CREATE INDEX idx_oauth_providers_enabled ON tenant_oauth_providers(tenant_id, enabled);

-- ============================================
-- Per-Tenant Webhook Endpoints
-- ============================================
CREATE TABLE tenant_webhook_endpoints (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    url VARCHAR(500) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    
    -- Event subscriptions
    events TEXT[] NOT NULL, -- ['user.created', 'session.revoked', etc.]
    
    -- Security
    signing_secret_hash VARCHAR(255) NOT NULL, -- For HMAC verification
    signature_header_name VARCHAR(100) DEFAULT 'X-Webhook-Signature',
    
    -- Retry configuration
    max_retries INTEGER DEFAULT 5,
    retry_schedule INTEGER[] DEFAULT '{60, 300, 900, 3600}',
    timeout_seconds INTEGER DEFAULT 30,
    
    -- Rate limiting
    rate_limit_requests INTEGER DEFAULT 100,
    rate_limit_window_seconds INTEGER DEFAULT 60,
    
    -- Status tracking
    last_triggered_at TIMESTAMPTZ,
    last_success_at TIMESTAMPTZ,
    last_failure_at TIMESTAMPTZ,
    failure_count INTEGER DEFAULT 0,
    
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID REFERENCES users(id)
);

CREATE INDEX idx_webhooks_tenant ON tenant_webhook_endpoints(tenant_id);
CREATE INDEX idx_webhooks_enabled ON tenant_webhook_endpoints(tenant_id, enabled);

-- ============================================
-- Per-Tenant Email Templates
-- ============================================
CREATE TABLE tenant_email_templates (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    template_type VARCHAR(100) NOT NULL, -- 'welcome', 'verification', 'password_reset', etc.
    
    -- Template content
    subject VARCHAR(500) NOT NULL,
    html_body TEXT,
    text_body TEXT,
    
    -- Localization
    language VARCHAR(10) NOT NULL DEFAULT 'en',
    
    -- Settings
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    from_address_override VARCHAR(255),
    from_name_override VARCHAR(255),
    
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by UUID REFERENCES users(id),
    
    UNIQUE(tenant_id, template_type, language)
);

CREATE INDEX idx_email_templates_tenant ON tenant_email_templates(tenant_id);
CREATE INDEX idx_email_templates_type ON tenant_email_templates(tenant_id, template_type);

-- ============================================
-- Per-Tenant Custom Domain Configuration
-- ============================================
CREATE TABLE tenant_custom_domains (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    domain VARCHAR(255) NOT NULL,
    
    -- Verification status
    verified BOOLEAN NOT NULL DEFAULT FALSE,
    verification_token VARCHAR(255),
    verification_method VARCHAR(50), -- 'dns_txt', 'file', 'meta_tag'
    verified_at TIMESTAMPTZ,
    
    -- SSL/TLS
    ssl_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    ssl_certificate_path TEXT,
    ssl_key_path TEXT,
    ssl_expires_at TIMESTAMPTZ,
    auto_ssl BOOLEAN NOT NULL DEFAULT TRUE, -- Use Let's Encrypt
    
    -- Configuration
    is_primary BOOLEAN NOT NULL DEFAULT FALSE,
    redirect_to_https BOOLEAN NOT NULL DEFAULT TRUE,
    
    -- DNS settings for verification
    required_dns_records JSONB DEFAULT '[]',
    
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    UNIQUE(tenant_id, domain)
);

CREATE INDEX idx_custom_domains_tenant ON tenant_custom_domains(tenant_id);
CREATE INDEX idx_custom_domains_domain ON tenant_custom_domains(domain);

-- ============================================
-- Per-Tenant Feature Flags (for gradual rollouts)
-- ============================================
CREATE TABLE tenant_feature_flags (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    flag_name VARCHAR(100) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    
    -- Gradual rollout
    rollout_percentage INTEGER DEFAULT 100, -- 0-100
    rollout_rules JSONB DEFAULT '[]', -- Target specific users/roles
    
    -- Metadata
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ, -- Auto-disable after date
    
    UNIQUE(tenant_id, flag_name)
);

CREATE INDEX idx_feature_flags_tenant ON tenant_feature_flags(tenant_id);

-- ============================================
-- Helper function to update settings with history tracking
-- ============================================
CREATE OR REPLACE FUNCTION update_tenant_setting(
    p_tenant_id UUID,
    p_category VARCHAR(50),
    p_new_value JSONB,
    p_changed_by UUID DEFAULT NULL,
    p_reason TEXT DEFAULT NULL
) RETURNS VOID AS $$
DECLARE
    v_previous_value JSONB;
    v_column_name TEXT;
BEGIN
    -- Map category to column name
    v_column_name := CASE p_category
        WHEN 'auth' THEN 'auth_settings'
        WHEN 'security' THEN 'security_settings'
        WHEN 'org' THEN 'org_settings'
        WHEN 'branding' THEN 'branding_settings'
        WHEN 'email' THEN 'email_settings'
        WHEN 'oauth' THEN 'oauth_settings'
        WHEN 'localization' THEN 'localization_settings'
        WHEN 'webhook' THEN 'webhook_settings'
        WHEN 'privacy' THEN 'privacy_settings'
        WHEN 'advanced' THEN 'advanced_settings'
        ELSE NULL
    END;
    
    IF v_column_name IS NULL THEN
        RAISE EXCEPTION 'Invalid settings category: %', p_category;
    END IF;
    
    -- Get previous value
    EXECUTE format('SELECT %I FROM tenant_settings WHERE tenant_id = $1', v_column_name)
    INTO v_previous_value
    USING p_tenant_id;
    
    -- Insert into history
    INSERT INTO tenant_settings_history (
        tenant_id, changed_by, change_type, 
        previous_value, new_value, reason
    ) VALUES (
        p_tenant_id, p_changed_by, p_category,
        v_previous_value, p_new_value, p_reason
    );
    
    -- Update the setting
    EXECUTE format('UPDATE tenant_settings SET %I = $1, updated_at = NOW(), updated_by = $2 WHERE tenant_id = $3', v_column_name)
    USING p_new_value, p_changed_by, p_tenant_id;
END;
$$ LANGUAGE plpgsql;

-- ============================================
-- RLS Policies
-- ============================================

-- Enable RLS
ALTER TABLE tenant_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_settings_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_oauth_providers ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_webhook_endpoints ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_email_templates ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_custom_domains ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_feature_flags ENABLE ROW LEVEL SECURITY;

-- Tenant isolation policies
CREATE POLICY tenant_isolation_settings ON tenant_settings
    FOR ALL TO vault_app
    USING (tenant_id = current_tenant_id());

CREATE POLICY tenant_isolation_settings_history ON tenant_settings_history
    FOR ALL TO vault_app
    USING (tenant_id = current_tenant_id());

CREATE POLICY tenant_isolation_oauth ON tenant_oauth_providers
    FOR ALL TO vault_app
    USING (tenant_id = current_tenant_id());

CREATE POLICY tenant_isolation_webhooks ON tenant_webhook_endpoints
    FOR ALL TO vault_app
    USING (tenant_id = current_tenant_id());

CREATE POLICY tenant_isolation_templates ON tenant_email_templates
    FOR ALL TO vault_app
    USING (tenant_id = current_tenant_id());

CREATE POLICY tenant_isolation_domains ON tenant_custom_domains
    FOR ALL TO vault_app
    USING (tenant_id = current_tenant_id());

CREATE POLICY tenant_isolation_flags ON tenant_feature_flags
    FOR ALL TO vault_app
    USING (tenant_id = current_tenant_id());

-- ============================================
-- Triggers for updated_at
-- ============================================
CREATE TRIGGER update_tenant_settings_updated_at
    BEFORE UPDATE ON tenant_settings
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_tenant_oauth_providers_updated_at
    BEFORE UPDATE ON tenant_oauth_providers
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_tenant_webhook_endpoints_updated_at
    BEFORE UPDATE ON tenant_webhook_endpoints
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_tenant_email_templates_updated_at
    BEFORE UPDATE ON tenant_email_templates
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_tenant_custom_domains_updated_at
    BEFORE UPDATE ON tenant_custom_domains
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_tenant_feature_flags_updated_at
    BEFORE UPDATE ON tenant_feature_flags
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================
-- Comments
-- ============================================
COMMENT ON TABLE tenant_settings IS 'Comprehensive per-tenant configuration settings';
COMMENT ON TABLE tenant_settings_history IS 'Audit trail for tenant setting changes';
COMMENT ON TABLE tenant_oauth_providers IS 'Per-tenant OAuth and SSO provider configurations';
COMMENT ON TABLE tenant_webhook_endpoints IS 'Per-tenant webhook endpoint configurations';
COMMENT ON TABLE tenant_email_templates IS 'Per-tenant customizable email templates';
COMMENT ON TABLE tenant_custom_domains IS 'Per-tenant custom domain configurations for white-labeling';
COMMENT ON TABLE tenant_feature_flags IS 'Per-tenant feature flags for gradual rollouts';
