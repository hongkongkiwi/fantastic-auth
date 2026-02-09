-- Add tenant_id to rate_limits for RLS compatibility

ALTER TABLE rate_limits
    ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE;

CREATE INDEX IF NOT EXISTS idx_rate_limits_tenant_key ON rate_limits(tenant_id, key);
