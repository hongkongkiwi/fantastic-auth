-- Ensure admin_api_keys has columns required by admin API routes

ALTER TABLE admin_api_keys
    ADD COLUMN IF NOT EXISTS created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

-- Backfill sensible defaults for legacy rows
UPDATE admin_api_keys
SET is_active = TRUE
WHERE is_active IS NULL;

-- Keep updated_at current for legacy rows
UPDATE admin_api_keys
SET updated_at = COALESCE(updated_at, created_at, NOW());

CREATE INDEX IF NOT EXISTS idx_admin_api_keys_active
    ON admin_api_keys(tenant_id, is_active)
    WHERE is_active = TRUE;
