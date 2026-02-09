-- Add security notification defaults and update audit retention defaults

-- Update default security settings to include notifications
ALTER TABLE tenant_settings
    ALTER COLUMN security_settings SET DEFAULT '{
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
        },
        "notifications": {
            "user": {
                "enabled": true,
                "events": ["login_failed", "login_blocked_risk", "password_changed", "password_reset", "mfa_enabled", "mfa_disabled"],
                "channels": ["email"]
            },
            "admin": {
                "enabled": true,
                "events": ["login_blocked_risk", "suspicious_login", "account_locked", "mfa_disabled", "security_policy_updated", "impersonation_started"],
                "channels": ["email"]
            },
            "admin_roles": ["owner", "admin"],
            "whatsapp_template_name": null
        }
    }'::jsonb;

-- Add notifications block to existing security settings if missing
UPDATE tenant_settings
SET security_settings = jsonb_set(
    security_settings,
    '{notifications}',
    '{
        "user": {
            "enabled": true,
            "events": ["login_failed", "login_blocked_risk", "password_changed", "password_reset", "mfa_enabled", "mfa_disabled"],
            "channels": ["email"]
        },
        "admin": {
            "enabled": true,
            "events": ["login_blocked_risk", "suspicious_login", "account_locked", "mfa_disabled", "security_policy_updated", "impersonation_started"],
            "channels": ["email"]
        },
        "admin_roles": ["owner", "admin"],
        "whatsapp_template_name": null
    }'::jsonb,
    true
)
WHERE security_settings->'notifications' IS NULL;

-- Update privacy settings default to 1 year retention
ALTER TABLE tenant_settings
    ALTER COLUMN privacy_settings SET DEFAULT jsonb_set(
        '{
            "analytics_enabled": true,
            "session_recording": false,
            "consent_required": true,
            "consent_types": ["tos", "privacy"],
            "data_retention_days": 365,
            "anonymize_ip": false,
            "allow_data_export": true,
            "allow_account_deletion": true,
            "deletion_grace_period_days": 30,
            "cookie_consent_required": true,
            "min_age_requirement": 13
        }'::jsonb,
        '{data_retention_days}',
        '365'::jsonb,
        true
    );

-- Update existing tenants that still use the old default (90 days)
UPDATE tenant_settings
SET privacy_settings = jsonb_set(
    privacy_settings,
    '{data_retention_days}',
    '365'::jsonb,
    true
)
WHERE (privacy_settings->>'data_retention_days') IS NULL
   OR privacy_settings->>'data_retention_days' = '90';
