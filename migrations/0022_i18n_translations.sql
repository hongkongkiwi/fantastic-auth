-- Migration: Internationalization (i18n) Translations Table
-- Creates table for storing custom translations

-- ============================================
-- i18n Translations Table
-- ============================================
-- Stores custom translations that can override built-in translations
-- Supports tenant-specific and global translations

CREATE TABLE IF NOT EXISTS i18n_translations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    lang VARCHAR(10) NOT NULL,
    key VARCHAR(255) NOT NULL,
    value TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- Ensure unique translations per tenant/lang/key
    UNIQUE (COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid), lang, key)
);

-- ============================================
-- Indexes
-- ============================================

-- Index for fast lookups by tenant, language and key
CREATE INDEX idx_i18n_translations_lookup 
    ON i18n_translations (tenant_id, lang, key);

-- Index for getting all translations for a language
CREATE INDEX idx_i18n_translations_lang 
    ON i18n_translations (lang);

-- Index for getting all translations for a tenant
CREATE INDEX idx_i18n_translations_tenant 
    ON i18n_translations (tenant_id);

-- Index for searching by key pattern
CREATE INDEX idx_i18n_translations_key 
    ON i18n_translations (key);

-- Index for updated_at (useful for sync operations)
CREATE INDEX idx_i18n_translations_updated 
    ON i18n_translations (updated_at);

-- ============================================
-- Row Level Security (RLS)
-- ============================================

-- Enable RLS
ALTER TABLE i18n_translations ENABLE ROW LEVEL SECURITY;

-- Policy: Users can only view translations for their tenant or global translations
CREATE POLICY i18n_tenant_isolation ON i18n_translations
    FOR ALL
    USING (
        tenant_id IS NULL 
        OR tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.current_user_role', true) = 'superadmin'
    );

-- ============================================
-- Triggers
-- ============================================

-- Auto-update updated_at timestamp
CREATE OR REPLACE FUNCTION update_i18n_translations_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_i18n_translations_updated_at
    BEFORE UPDATE ON i18n_translations
    FOR EACH ROW
    EXECUTE FUNCTION update_i18n_translations_updated_at();

-- ============================================
-- Comments
-- ============================================

COMMENT ON TABLE i18n_translations IS 'Custom translations for i18n support';
COMMENT ON COLUMN i18n_translations.tenant_id IS 'Tenant ID for tenant-specific translations, NULL for global';
COMMENT ON COLUMN i18n_translations.lang IS 'Language code (e.g., en, es, fr)';
COMMENT ON COLUMN i18n_translations.key IS 'Translation key (e.g., errors.invalid_credentials)';
COMMENT ON COLUMN i18n_translations.value IS 'Translated text value';

-- ============================================
-- Seed data: Default translations can be inserted here
-- Example: Custom error messages for a specific tenant
-- ============================================

-- Example seed (commented out, can be enabled as needed):
-- INSERT INTO i18n_translations (tenant_id, lang, key, value) VALUES
--     (NULL, 'en', 'custom.brand_name', 'My Custom Vault'),
--     (NULL, 'es', 'custom.brand_name', 'Mi Vault Personalizado');
