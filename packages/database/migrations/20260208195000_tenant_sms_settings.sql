-- Add per-tenant SMS settings with provider overrides

ALTER TABLE tenant_settings
    ADD COLUMN IF NOT EXISTS sms_settings JSONB NOT NULL DEFAULT '{}'::jsonb;

-- Update helper function to support sms settings category
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
        WHEN 'sms' THEN 'sms_settings'
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
